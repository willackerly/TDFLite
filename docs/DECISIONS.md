# Architecture Decisions & API Reference

## Key Architecture Decisions

- idplite uses `Audience` config to separate issuer URL from token audience (fixes auth mismatch)
- Custom claims on Identity struct emit as top-level JWT claims for subject mapping selectors
- loader.DefaultConfig takes 3 args: pgPort, idpPort, serverPort (audience derived from serverPort)
- Entity resolution uses "claims" mode — JWT claims are the entity, no Keycloak admin API

## Connect Protocol API

- Pattern: `POST /{service}/{method}` with `Connect-Protocol-Version: 1` header
- Namespace: `policy.namespaces.NamespaceService/CreateNamespace`
- Attributes: `policy.attributes.AttributesService/CreateAttribute` (values inline)
- Subject mappings: `policy.subjectmapping.SubjectMappingService/CreateSubjectMapping`
- Enums use full names: `ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY`, `SUBJECT_MAPPING_OPERATOR_ENUM_IN`
- JSON field names use camelCase (protobuf JSON encoding): `namespaceId`, `attributeValueId`
