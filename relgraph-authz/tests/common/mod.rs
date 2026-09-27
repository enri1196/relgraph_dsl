use relgraph_authz::{CheckRequest, ObjectRef, RelationName, Subject, TenantId};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

pub const DIRECT_MODEL: &str = "model\nschema 1.1\ntype user\ntype group\ntype document\n  relations\n    define viewer: [user]\n";

pub fn request(
    tenant: &str,
    subject_type: &str,
    subject_id: &str,
    object_type: &str,
    object_id: &str,
    relation: &str,
) -> CheckRequest {
    CheckRequest::new(
        TenantId::new(tenant).unwrap(),
        Subject::new(subject_type, subject_id).unwrap(),
        ObjectRef::new(object_type, object_id).unwrap(),
        RelationName::new(relation).unwrap(),
    )
}

pub fn object(object_type: &str, object_id: &str) -> ObjectRef {
    ObjectRef::new(object_type, object_id).unwrap()
}

pub fn relation(relation: &str) -> RelationName {
    RelationName::new(relation).unwrap()
}

pub fn subject(subject_type: &str, subject_id: &str) -> Subject {
    Subject::new(subject_type, subject_id).unwrap()
}

pub fn tenant(tenant: &str) -> TenantId {
    TenantId::new(tenant).unwrap()
}

pub fn block_on<F: Future>(future: F) -> F::Output {
    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly yielded"),
    }
}
