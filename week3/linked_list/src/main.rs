use linked_list::LinkedList;
pub mod linked_list;

fn main() {
    let mut list: LinkedList<u32> = LinkedList::new();
    assert!(list.is_empty());
    assert_eq!(list.get_size(), 0);
    for i in 1..12 {
        list.push_front(i);
    }
    println!("{}", list);
    println!("list size: {}", list.get_size());
    println!("top element: {}", list.pop_front().unwrap());
    println!("{}", list);
    println!("size: {}", list.get_size());
    println!("{}", list.to_string()); // ToString impl for anything impl Display
                                      //
    let mut list2 = list.clone();
    println!("{}", list2);
    println!("list size: {}", list2.get_size());
    println!("top element: {}", list2.pop_front().unwrap());
    println!("{}", list2);
    println!("size: {}", list2.get_size());
    println!("{}", list2.to_string());

    // let list3 = list2.clone();
    // println!("{}", list2.eq(&list3));
    // list2.pop_front().unwrap();
    // println!("{}", list2.eq(&list3));
    // list2.push_front(9);
    // println!("{}", list2.eq(&list3));
    // If you implement iterator trait:
    for val in list {
        println!("{}", val);
    }
}
