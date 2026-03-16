PROVIDER := env_var_or_default("PROVIDER", "google")
TIMEOUT := env_var_or_default("TIMEOUT", "60")
REMEDIATE := env_var_or_default("REMEDIATE", "false")
AGENTIC_APPS_PATH := env_var_or_default("AGENTIC_APPS_PATH", "")
TOURIST_CMD := env_var_or_default("TOURIST_CMD", "")
SHADI_OP_ACCOUNT := env_var_or_default("SHADI_OP_ACCOUNT", "my.1password.com")

shadi_tmp_dir := env_var_or_default("SHADI_TMP_DIR", "./.tmp")
operator_agent_id_override := env_var_or_default("SHADI_OPERATOR_AGENT_ID", "")
default_agent_id := if operator_agent_id_override != "" { operator_agent_id_override } else { "secops_agent" }
agent_id_override := env_var_or_default("SHADI_AGENT_ID", "")
effective_agent_id := if agent_id_override != "" { agent_id_override } else { default_agent_id }
shared_memory_db := env_var_or_default("SHADI_MEMORY_DB", "")
secops_memory_db_override := env_var_or_default("SHADI_SECOPS_MEMORY_DB", "")
default_secops_memory_db := shadi_tmp_dir + "/" + effective_agent_id + "/shadi-secops/secops_memory.db"
secops_memory_db := if secops_memory_db_override != "" { secops_memory_db_override } else if shared_memory_db != "" { shared_memory_db } else { default_secops_memory_db }