use super::model::CompiledModel;
use super::request::{AuthorizationDecision, AuthorizationError, CheckRequest, EvaluationLimits};
use super::store::{RelationshipReadSession, RelationshipStore, StoreErrorKind, TupleSubject};
use openfga_dsl::RelationExpression;

pub(crate) async fn check<S: RelationshipStore>(
    compiled: &CompiledModel,
    store: &S,
    limits: EvaluationLimits,
    request: &CheckRequest,
) -> Result<AuthorizationDecision, AuthorizationError> {
    let object_type_name = request.object().type_name().as_str();
    let object_type_id = compiled
        .type_id(object_type_name)
        .ok_or_else(|| AuthorizationError::UnknownObjectType(object_type_name.to_owned()))?;
    if compiled
        .relation_id(object_type_id, request.relation().as_str())
        .is_none()
    {
        return Err(AuthorizationError::UnknownRelation {
            object_type: object_type_name.to_owned(),
            relation: request.relation().as_str().to_owned(),
        });
    }

    let subject_type_name = request.subject().type_name().as_str();
    compiled
        .type_id(subject_type_name)
        .ok_or_else(|| AuthorizationError::UnknownSubjectType(subject_type_name.to_owned()))?;

    let relation = compiled.schema().type_definitions[object_type_id]
        .relations
        .iter()
        .find(|relation| relation.name == request.relation().as_str())
        .expect("compiled relation index points at a declared relation");
    let RelationExpression::DirectAssignment(targets) = &relation.definition.expression else {
        return Err(AuthorizationError::InvalidTuple(
            "compiled relation is outside the direct-assignment evaluator profile",
        ));
    };
    let subject_type_is_allowed = targets.iter().any(|target| {
        target.target_type == subject_type_name
            && target.relation_or_wildcard.is_none()
            && target.condition.is_none()
    });
    if !subject_type_is_allowed {
        return Ok(AuthorizationDecision::Deny);
    }

    let maximum = limits.max_tuples_scanned();
    let session = store
        .begin_read(request.tenant())
        .await
        .map_err(|error| map_store_error(error, maximum))?;
    let tuples = session
        .tuples(request.object(), request.relation(), maximum)
        .await
        .map_err(|error| map_store_error(error, maximum))?;
    if tuples.len() > maximum {
        return Err(AuthorizationError::EvaluationLimitExceeded {
            maximum_tuples: maximum,
        });
    }

    let mut allowed = false;
    for tuple in &tuples {
        if tuple.tenant() != request.tenant() {
            return Err(AuthorizationError::InvalidTuple(
                "tuple belongs to a different tenant",
            ));
        }
        if tuple.object() != request.object() || tuple.relation() != request.relation() {
            return Err(AuthorizationError::InvalidTuple(
                "tuple does not match the requested object and relation",
            ));
        }
        if tuple.condition().is_some() {
            return Err(AuthorizationError::InvalidTuple(
                "conditional tuples are not supported by this runtime profile",
            ));
        }

        let TupleSubject::Direct(tuple_subject) = tuple.subject() else {
            return Err(AuthorizationError::InvalidTuple(
                "userset and wildcard tuples are not supported by this runtime profile",
            ));
        };
        let tuple_subject_type_name = tuple_subject.type_name().as_str();
        compiled
            .type_id(tuple_subject_type_name)
            .ok_or(AuthorizationError::InvalidTuple(
                "tuple subject type is absent from the authorization model",
            ))?;
        let tuple_subject_type_is_allowed = targets.iter().any(|target| {
            target.target_type == tuple_subject_type_name
                && target.relation_or_wildcard.is_none()
                && target.condition.is_none()
        });
        if !tuple_subject_type_is_allowed {
            return Err(AuthorizationError::InvalidTuple(
                "tuple subject type is incompatible with the relation",
            ));
        }

        if tuple_subject.type_name() == request.subject().type_name()
            && tuple_subject.id() == request.subject().id()
        {
            allowed = true;
        }
    }

    Ok(if allowed {
        AuthorizationDecision::Allow
    } else {
        AuthorizationDecision::Deny
    })
}

fn map_store_error(error: super::store::StoreError, maximum: usize) -> AuthorizationError {
    if error.kind() == StoreErrorKind::TupleLimitExceeded {
        AuthorizationError::EvaluationLimitExceeded {
            maximum_tuples: maximum,
        }
    } else {
        AuthorizationError::Store(error)
    }
}
