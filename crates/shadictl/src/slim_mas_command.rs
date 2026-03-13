use super::*;

pub(crate) fn run_slim_mas_command(cli: SlimMasCli) -> ExitCode {
    let config = match load_mas_config(&cli.config) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(2);
        }
    };
    let store = default_secret_store();
    let mut fetch = |key: &str| {
        let secret = store
            .get(key)
            .map_err(|_| format!("keychain lookup failed for {}", key))?;
        let value = secret.expose(|bytes| bytes.to_vec());
        String::from_utf8(value).map_err(|_| "secret is not utf-8".to_string())
    };

    match cli.command {
        SlimMasCommand::Admit { group, did, role } => {
            let group_name = match resolve_group(&config, group.as_deref()) {
                Ok(group_name) => group_name,
                Err(err) => {
                    eprintln!("{}", err);
                    return ExitCode::from(2);
                }
            };
            let group_config = match config
                .group(group_name)
                .ok_or_else(|| format!("group '{}' not found", group_name))
            {
                Ok(group) => group,
                Err(err) => {
                    eprintln!("{}", err);
                    return ExitCode::from(2);
                }
            };
            let group_config = match resolve_group_dids(group_config, &mut fetch) {
                Ok(group) => group,
                Err(err) => {
                    eprintln!("{}", err);
                    return ExitCode::from(2);
                }
            };
            let did = match slim_mas::resolve_did_ref(&did, &mut fetch) {
                Ok(did) => did,
                Err(err) => {
                    eprintln!("{}", err);
                    return ExitCode::from(2);
                }
            };

            if is_member_allowed(&group_config, &did, role.as_deref()) {
                println!("allow");
                ExitCode::from(0)
            } else {
                println!("deny");
                ExitCode::from(3)
            }
        }
        SlimMasCommand::ListGroups => {
            for name in config.groups.keys() {
                println!("{}", name);
            }
            ExitCode::from(0)
        }
        SlimMasCommand::ListMembers { group } => {
            let group_name = match resolve_group(&config, group.as_deref()) {
                Ok(group_name) => group_name,
                Err(err) => {
                    eprintln!("{}", err);
                    return ExitCode::from(2);
                }
            };
            let group_config = match config
                .group(group_name)
                .ok_or_else(|| format!("group '{}' not found", group_name))
            {
                Ok(group) => group,
                Err(err) => {
                    eprintln!("{}", err);
                    return ExitCode::from(2);
                }
            };
            let group_config = match resolve_group_dids(group_config, &mut fetch) {
                Ok(group) => group,
                Err(err) => {
                    eprintln!("{}", err);
                    return ExitCode::from(2);
                }
            };
            for member in &group_config.members {
                match member.role.as_deref() {
                    Some(role) => println!("{} {}", member.did, role),
                    None => println!("{}", member.did),
                }
            }
            ExitCode::from(0)
        }
        SlimMasCommand::Validate => match resolve_group(&config, None) {
            Ok(_) => ExitCode::from(0),
            Err(err) => {
                eprintln!("{}", err);
                ExitCode::from(2)
            }
        },
    }
}
