# Intentionally vulnerable: the pattern an AI coding assistant tends to produce for "NL to SQL".
def naive_hunt(store, llm, question):
    sql = llm.chat("Translate to SQL", question)
    return store.query(sql)  # model output executed directly


def guarded_hunt(store, llm, question, validate_sql):
    sql = llm.chat("Translate to SQL", question)
    return store.query(validate_sql(sql))  # ok: sanitized
