use node::op::Op;

#[test]
fn round_trip() {
    for op in [
        None,
        Some(Op::Keygen {
            structure: shrincs::Structure::balanced(11),
        }),
        Some(Op::Keygen {
            structure: shrincs::Structure::unbalanced(255),
        }),
        Some(Op::Sign {
            msg: b"abcdefghij".to_vec(),
            ctx: vec![],
            exact: true,
            cache: false,
        }),
        Some(Op::SignStateless {
            msg: vec![],
            ctx: b"ctx".to_vec(),
            exact: false,
            cache: true,
        }),
    ] {
        assert_eq!(Op::decode(&Op::encode(&op)), Some(op));
    }
}

#[test]
fn rejects_malformed() {
    assert_eq!(Op::decode(&[]), None);
    assert_eq!(Op::decode(&[9]), None);
    assert_eq!(Op::decode(&[1, 256, 1]), None);
    assert_eq!(Op::decode(&[1, 2, 2]), None);
    assert_eq!(Op::decode(&[2, 4, 0, 0]), None);
    assert_eq!(Op::decode(&[2, 100, 0]), None);
    assert_eq!(Op::decode(&[2, u64::MAX]), None);
}

#[test]
fn cluster_file() {
    let text = "# id order\n10.0.0.1 8080\n10.0.0.2 9000 # comment\n\n10.0.0.3 8080\n10.0.0.4 8080\n";
    assert_eq!(
        node::read_cluster(text).unwrap(),
        ["10.0.0.1:8080", "10.0.0.2:9000", "10.0.0.3:8080", "10.0.0.4:8080"]
    );
    assert!(node::read_cluster("a 1\nb 2\nc 3").is_err());
    assert!(node::read_cluster("a 1\nb 2\nc 3\nd x").is_err());
}
