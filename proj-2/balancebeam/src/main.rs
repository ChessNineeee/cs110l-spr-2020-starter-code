mod request;
mod response;

use clap::Parser;
use http::StatusCode;
// use num_cpus;
use rand::{Rng, SeedableRng};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
// use threadpool::ThreadPool;
use tokio::{
    io,
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::sleep,
    time::Duration,
};

/// Contains information parsed from the command-line invocation of balancebeam. The Clap macros
/// provide a fancy way to automatically construct a command-line argument parser.
#[derive(Parser, Debug)]
#[command(about = "Fun with load balancing")]
struct CmdOptions {
    #[arg(short, long, default_value = "0.0.0.0:1100")]
    bind: String,
    #[arg(short, long)]
    upstream: Vec<String>,
    #[arg(long, default_value = "10")]
    active_health_check_interval: usize,
    #[arg(long, default_value = "/")]
    active_health_check_path: String,
    #[arg(long, default_value = "0")]
    max_requests_per_minute: usize,
}

/// Contains information about the state of balancebeam (e.g. what servers we are currently proxying
/// to, what servers have failed, rate limiting counts, etc.)
///
/// You should add fields to this struct in later milestones.
struct ProxyState {
    /// How frequently we check whether upstream servers are alive (Milestone 4)
    #[allow(dead_code)]
    active_health_check_interval: usize,
    /// Where we should send requests when doing active health checks (Milestone 4)
    #[allow(dead_code)]
    active_health_check_path: String,
    /// Maximum number of requests an individual IP can make in a minute (Milestone 5)
    #[allow(dead_code)]
    max_requests_per_minute: usize,
    /// Addresses of servers that we are proxying to
    upstream_addresses: Vec<String>,
    /// Addresses of dead servers
    dead_upstreams: Arc<Mutex<HashSet<String>>>,
    /// Request counters for each <client upstream
    request_counters: Arc<Mutex<HashMap<String, usize>>>,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // Initialize the logging library. You can print log messages using the `log` macros:
    // https://docs.rs/log/0.4.8/log/ You are welcome to continue using print! statements; this
    // just looks a little prettier.
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "debug");
    }
    pretty_env_logger::init();

    // Parse the command line arguments passed to this program
    let options = CmdOptions::parse();
    if options.upstream.len() < 1 {
        log::error!("At least one upstream server must be specified using the --upstream option.");
        std::process::exit(1);
    }

    // Start listening for connections
    let listener = match TcpListener::bind(&options.bind).await {
        Ok(listener) => listener,
        Err(err) => {
            log::error!("Could not bind to {}: {}", options.bind, err);
            std::process::exit(1);
        }
    };
    log::info!("Listening for requests on {}", options.bind);

    // Handle incoming connections
    let state = ProxyState {
        upstream_addresses: options.upstream,
        active_health_check_interval: options.active_health_check_interval,
        active_health_check_path: options.active_health_check_path,
        max_requests_per_minute: options.max_requests_per_minute,
        dead_upstreams: Arc::new(Mutex::new(HashSet::new())),
        request_counters: Arc::new(Mutex::new(HashMap::new())),
    };

    let state = Arc::new(state);
    // Milestone 1: Add multithreading
    // let num_threads = num_cpus::get();
    // let pool = ThreadPool::new(num_threads);
    // for stream in listener.incoming() {
    //     if let Ok(stream) = stream {
    //         // Handle the connection!
    //         let state = state.clone();
    //         //         pool.execute(move || {
    //         //             handle_connection(stream, &state);
    //         //         });
    //     }
    // }

    // Milestone 4: Active health checks
    {
        let state = state.clone();
        tokio::spawn(async move { active_health_check_loop(state).await });
    }

    // Milestone 5: Rate limiting
    {
        let state = state.clone();
        tokio::spawn(async move { reset_request_counters(&state).await });
    }

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            handle_connection(stream, &state).await;
        });
    }
}

async fn reset_request_counters(state: &ProxyState) {
    // insert all upstream counters
    for it in state.upstream_addresses.iter() {
        insert_request_counters(state, it).await;
    }

    loop {
        // clean_interval = 1min
        sleep(Duration::from_secs(60)).await;

        {
            let mut counters = state.request_counters.lock().await;
            for (_, counter) in counters.iter_mut() {
                *counter = 0;
            }
        }
    }
}

async fn insert_request_counters(state: &ProxyState, upstream_id: &String) {
    let mut counters = state.request_counters.lock().await;
    counters.insert(upstream_id.clone(), 0);
}

async fn increment_request_counters(state: &ProxyState, upstream_id: &String) {
    let mut counters = state.request_counters.lock().await;
    let counter = counters.get_mut(upstream_id).unwrap();
    *counter += 1;
}

async fn is_limited(state: &ProxyState, upstream_id: &String) -> bool {
    if state.max_requests_per_minute == 0 {
        return false;
    }

    let counters = state.request_counters.lock().await;
    let counter = counters.get(upstream_id).unwrap();

    if *counter >= state.max_requests_per_minute {
        return true;
    }
    return false;
}

async fn active_health_check_loop(state: Arc<ProxyState>) {
    loop {
        sleep(Duration::from_secs(
            state.active_health_check_interval as u64,
        ))
        .await;

        for i in 0..state.upstream_addresses.len() {
            let state = state.clone();
            tokio::spawn(async move {
                active_health_check(&state, i).await;
            });
        }
    }
}

async fn active_health_check(state: &ProxyState, idx: usize) {
    let upstream_ip = state.upstream_addresses.iter().nth(idx).unwrap();
    let request = make_health_check_request(&state.active_health_check_path, upstream_ip);

    // do_connect
    // connect to upstream
    let upstream_conn = do_connect(upstream_ip).await;
    if upstream_conn.is_err() {
        add_dead_upstream(state, upstream_ip).await;
        return;
    }
    let mut upstream_conn = upstream_conn.unwrap();
    // write_to_stream
    // forward health-check request to upstream
    let forward_result = request::write_to_stream(&request, &mut upstream_conn).await;
    if forward_result.is_err() {
        add_dead_upstream(state, upstream_ip).await;
        return;
    }
    // read_from_stream
    // receive response from upstream
    let response = response::read_from_stream(&mut upstream_conn, request.method()).await;
    if response.is_err() {
        add_dead_upstream(state, upstream_ip).await;
        return;
    }
    let response = response.unwrap();
    // HTTP 200
    // check response's status
    let status = response.status();
    if status != StatusCode::OK {
        add_dead_upstream(state, upstream_ip).await;
        return;
    }

    // upstream is healthy!
    remove_dead_upstream(state, upstream_ip).await;
    return;
}

async fn add_dead_upstream(state: &ProxyState, stream_addr: &String) {
    let mut dead_upstreams = state.dead_upstreams.lock().await;
    dead_upstreams.insert(stream_addr.clone());
}

async fn remove_dead_upstream(state: &ProxyState, stream_addr: &String) {
    let mut dead_upstreams = state.dead_upstreams.lock().await;
    dead_upstreams.remove(stream_addr);
}

async fn get_available_upstream(state: &ProxyState) -> Result<&String, std::io::Error> {
    let dead_upstreams = state.dead_upstreams.lock().await;
    let upstream_num = state.upstream_addresses.len();
    if dead_upstreams.len() == upstream_num {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "no available upstream",
        ));
    }

    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut upstream_idx = rng.gen_range(0..state.upstream_addresses.len());
    let mut upstream_addr = &state.upstream_addresses[upstream_idx];

    let mut is_dead_upstream = dead_upstreams.contains(upstream_addr);
    while is_dead_upstream {
        upstream_idx = (upstream_idx + 1) % upstream_num;
        upstream_addr = &state.upstream_addresses[upstream_idx];

        is_dead_upstream = dead_upstreams.contains(upstream_addr);
    }

    Ok(upstream_addr)
}

async fn do_connect(upstream_ip: &String) -> Result<TcpStream, std::io::Error> {
    TcpStream::connect(upstream_ip).await.or_else(|err| {
        log::error!("Failed to connect to upstream {}: {}", upstream_ip, err);
        Err(err)
    })
}

fn make_health_check_request(path: &String, upstream: &String) -> http::Request<Vec<u8>> {
    http::Request::builder()
        .method(http::Method::GET)
        .uri(path)
        .header("Host", upstream)
        .body(Vec::new())
        .unwrap()
}

async fn connect_to_upstream(state: &ProxyState) -> Result<TcpStream, std::io::Error> {
    let mut upstream_ip = get_available_upstream(state).await?;
    let mut res = do_connect(upstream_ip).await;
    // TODO: implement failover (milestone 3)
    if res.is_ok() {
        return res;
    }

    while res.is_err() {
        add_dead_upstream(state, upstream_ip).await;
        upstream_ip = get_available_upstream(state).await?;
        res = do_connect(upstream_ip).await;
    }
    return res;
}

async fn send_response(client_conn: &mut TcpStream, response: &http::Response<Vec<u8>>) {
    let client_ip = client_conn.peer_addr().unwrap().ip().to_string();
    log::info!(
        "{} <- {}",
        client_ip,
        response::format_response_line(&response)
    );
    if let Err(error) = response::write_to_stream(&response, client_conn).await {
        log::warn!("Failed to send response to client: {}", error);
        return;
    }
}

async fn read_request_from_client(client_conn: &mut TcpStream) -> Option<http::Request<Vec<u8>>> {
    match request::read_from_stream(client_conn).await {
        Ok(request) => Some(request),
        // Handle case where client closed connection and is no longer sending requests
        Err(request::Error::IncompleteRequest(0)) => {
            log::debug!("Client finished sending requests. Shutting down connection");
            return None;
        }
        // Handle I/O error in reading from the client
        Err(request::Error::ConnectionError(io_err)) => {
            log::info!("Error reading request from client stream: {}", io_err);
            return None;
        }
        Err(error) => {
            log::debug!("Error parsing request: {:?}", error);
            let response = response::make_http_error(match error {
                request::Error::IncompleteRequest(_)
                | request::Error::MalformedRequest(_)
                | request::Error::InvalidContentLength
                | request::Error::ContentLengthMismatch => http::StatusCode::BAD_REQUEST,
                request::Error::RequestBodyTooLarge => http::StatusCode::PAYLOAD_TOO_LARGE,
                request::Error::ConnectionError(_) => http::StatusCode::SERVICE_UNAVAILABLE,
            });
            send_response(client_conn, &response).await;
            return None;
        }
    }
}

async fn handle_connection(mut client_conn: TcpStream, state: &ProxyState) {
    let client_addr = client_conn.peer_addr().unwrap().to_string();
    log::info!("Connection received from {}", client_addr);

    // Open a connection to a random destination server
    let mut upstream_conn = match connect_to_upstream(state).await {
        Ok(stream) => stream,
        Err(_error) => {
            let response = response::make_http_error(http::StatusCode::BAD_GATEWAY);
            send_response(&mut client_conn, &response).await;
            return;
        }
    };
    let upstream_addr = upstream_conn.peer_addr().unwrap().to_string();

    // The client may now send us one or more requests. Keep trying to read requests until the
    // client hangs up or we get an error.
    loop {
        // Read a request from the client
        let request = read_request_from_client(&mut client_conn).await;
        if request.is_none() {
            break;
        }

        // rate-limiting
        if is_limited(state, &upstream_addr).await {
            let response = response::make_http_error(http::StatusCode::TOO_MANY_REQUESTS);
            send_response(&mut client_conn, &response).await;
            continue;
        }
        increment_request_counters(state, &upstream_addr).await;

        let mut request = request.unwrap();
        log::info!(
            "{} -> {}: {}",
            client_addr,
            upstream_addr,
            request::format_request_line(&request)
        );

        // Add X-Forwarded-For header so that the upstream server knows the client's IP address.
        // (We're the ones connecting directly to the upstream server, so without this header, the
        // upstream server will only know our IP, not the client's.)
        request::extend_header_value(&mut request, "x-forwarded-for", &client_addr);

        // Forward the request to the server
        if let Err(error) = request::write_to_stream(&request, &mut upstream_conn).await {
            log::error!(
                "Failed to send request to upstream {}: {}",
                upstream_addr,
                error
            );
            let response = response::make_http_error(http::StatusCode::BAD_GATEWAY);
            send_response(&mut client_conn, &response).await;
            return;
        }
        log::debug!("Forwarded request to server");

        // Read the server's response
        let response = match response::read_from_stream(&mut upstream_conn, request.method()).await
        {
            Ok(response) => response,
            Err(error) => {
                log::error!("Error reading response from server: {:?}", error);
                let response = response::make_http_error(http::StatusCode::BAD_GATEWAY);
                send_response(&mut client_conn, &response).await;
                return;
            }
        };
        // Forward the response to the client
        send_response(&mut client_conn, &response).await;
        log::debug!("Forwarded response to client");
    }
}
