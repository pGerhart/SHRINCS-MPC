use node::agreement::Agreement;

#[test]
fn rejects_malformed_control_messages() {
    let bad: [Vec<u64>; 5] = [vec![], vec![1], vec![1, 0, 9], vec![2, 0, 1, 2], vec![1, 2, 0]];
    for m in bad {
        assert!(Agreement::new(0).receive(1, m.clone()).is_err(), "{m:?}");
    }
    let mut a = Agreement::new(0);
    assert!(a.receive(1, vec![1, 0, 0]).is_ok());
    assert!(a.receive(1, vec![1, 0, 0]).is_err(), "second proposal for one slot");
    let mut a = Agreement::new(0);
    assert!(a.receive(2, vec![1, 1, 0]).is_ok());
    assert!(a.receive(2, vec![2, 1, 0, 0, 0, 0]).is_ok());
    assert!(a.receive(2, vec![1, 1, 0]).is_err(), "too far ahead");
}
