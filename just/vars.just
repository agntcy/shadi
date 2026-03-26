SHADI_OP_ACCOUNT := env_var_or_default("SHADI_OP_ACCOUNT", "my.1password.com")

shadi_tmp_dir := env_var_or_default("SHADI_TMP_DIR", "./.tmp")
operator_agent_id_override := env_var_or_default("SHADI_OPERATOR_AGENT_ID", "")
default_agent_id := if operator_agent_id_override != "" { operator_agent_id_override } else { "agent" }
agent_id_override := env_var_or_default("SHADI_AGENT_ID", "")
effective_agent_id := if agent_id_override != "" { agent_id_override } else { default_agent_id }
shared_memory_db := env_var_or_default("SHADI_MEMORY_DB", "")