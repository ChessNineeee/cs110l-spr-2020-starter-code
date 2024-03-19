use crossbeam_channel;
use std::{thread, time};

fn parallel_map<T, U, F>(mut input_vec: Vec<T>, num_threads: usize, f: F) -> Vec<U>
where
    F: FnOnce(T) -> U + Send + Copy + 'static,
    T: Send + 'static,
    U: Send + 'static + Default,
{
    let mut output_vec: Vec<U> = Vec::with_capacity(input_vec.len());
    output_vec.resize_with(input_vec.len(), Default::default);
    // TODO: implement parallel map!
    let (input_sender, input_receiver) = crossbeam_channel::unbounded::<(usize, T)>();
    let (output_sender, output_receiver) = crossbeam_channel::unbounded::<(usize, U)>();
    let mut threads = Vec::new();
    for _ in 0..num_threads - 1 {
        let input_receiver = input_receiver.clone();
        let output_sender = output_sender.clone();

        threads.push(thread::spawn(move || {
            while let Ok((next_input_p, next_input)) = input_receiver.recv() {
                let output = (next_input_p, f(next_input));
                output_sender.send(output).expect("Error sending output");
            }
            drop(output_sender);
        }));
    }

    let len = input_vec.len();
    for i in 0..len {
        let input_p = len - i - 1;
        input_sender
            .send((input_p, input_vec.pop().unwrap()))
            .expect("Error sending input");
    }

    drop(input_sender);

    drop(output_sender);

    while let Ok((next_output_p, next_output)) = output_receiver.recv() {
        output_vec[next_output_p] = next_output;
    }

    for thread in threads {
        thread.join().expect("Panic occurred in thread");
    }

    output_vec
}

fn main() {
    let v = vec![6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 12, 18, 11, 5, 20];
    let squares = parallel_map(v, 10, |num| {
        println!("{} squared is {}", num, num * num);
        thread::sleep(time::Duration::from_millis(500));
        num * num
    });
    println!("squares: {:?}", squares);
}
