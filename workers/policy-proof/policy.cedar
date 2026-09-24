// The predicate is intentionally public; only context.limit is private.
permit (
    principal is Agent,
    action == Action::"purchase",
    resource == Resource::"globex:research-report"
)
when {
    context.audience == "globex" &&
    context.recipient == "globex" &&
    context.currency == "USD" &&
    context.asset == "iso4217:USD" &&
    context.network == "simulation" &&
    context.amount > 0 &&
    context.amount <= context.limit
};
