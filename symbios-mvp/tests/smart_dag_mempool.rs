use symbios_mvp::dag_mempool::SmartDagMempool;
use symbios_mvp::types::{PublicKey, Transaction};

#[tokio::test]
async fn test_priority_order() {
    // Create validators list (dummy)
    let validators = vec![PublicKey::new("v1".to_string())];
    let mut mempool = SmartDagMempool::new(validators, 10);

    // Three transactions with different fees
    let tx_low = Transaction::new_with_fee(
        PublicKey::new("a".to_string()),
        PublicKey::new("b".to_string()),
        10,
        1,
        0,
    );
    let tx_high = Transaction::new_with_fee(
        PublicKey::new("c".to_string()),
        PublicKey::new("d".to_string()),
        10,
        100,
        1,
    );
    let tx_mid = Transaction::new_with_fee(
        PublicKey::new("e".to_string()),
        PublicKey::new("f".to_string()),
        10,
        50,
        2,
    );

    mempool.add_transaction(tx_low.clone()).await.unwrap();
    mempool.add_transaction(tx_high.clone()).await.unwrap();
    mempool.add_transaction(tx_mid.clone()).await.unwrap();

    // pop transactions (consumes)
    let popped = mempool.get_pending_transactions(3).await.unwrap();
    assert_eq!(popped[0].fee, 100);
    assert_eq!(popped[1].fee, 50);
    assert_eq!(popped[2].fee, 1);
}
