use std::{sync::Arc, time::Duration};

use axum::extract::FromRef;
use tokio::time::interval;

use crate::{
    challenge::ChallengeController,
    config::AppConfig,
    db::{Database, repository::UserRepository},
    node_manager::NodeManager,
    token::TokenIssuer,
    user::UserManager,
};

#[derive(Clone, FromRef)]
pub struct AppState {
    pub challenge_controller: Arc<ChallengeController>,
    pub node_manager: Arc<NodeManager>,
    pub database: Arc<Database>,
    pub user_manager: Arc<UserManager>,
}

impl FromRef<AppState> for UserRepository {
    fn from_ref(input: &AppState) -> Self {
        input.database.user_repository.clone()
    }
}

impl AppState {
    pub async fn new(config: &AppConfig) -> Self {
        let node_manager = Arc::new(NodeManager::new(config));
        let database = Arc::new(Database::new(config).await.expect("failed to create database connection"));

        let token_issuer = TokenIssuer::new(config);
        let user_manager = Arc::new(UserManager::new(database.user_repository.clone(), token_issuer));

        Self {
            challenge_controller: Arc::new(ChallengeController::new(config, node_manager.clone())),
            node_manager,
            database,
            user_manager,
        }
    }

    pub fn token_issuer(&self) -> &TokenIssuer {
        &self.user_manager.token_issuer()
    }

    pub async fn run_maintenance_tasks(self) {
        // let mut nm_cleanup = interval(Duration::from_mins(1));
        let mut cc_cleanup = interval(Duration::from_mins(1));

        loop {
            tokio::select! {
                _ = cc_cleanup.tick() => {
                    self.challenge_controller.run_cleanup();
                }
            }
        }
    }
}
