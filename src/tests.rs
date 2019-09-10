#[cfg(test)]
use super::stream::Stream;

#[test]
fn biggun() {
    let mut s =  Stream::new().unwrap();
    s.add_interval_filter(1567756800,1567756801).unwrap();
    s.add_filter("collector rrc00 and type ribs".to_string()).unwrap();
    
    let mut count = 0;
    for x in s.iter().unwrap() {
        if let Ok(_elem) = x {
            count += 1;
        } else {
            break;
        }
        if count >= 10 {
            break;
        }
    }
    assert!(count == 10);
}
