use base64::Engine;
use pbkdf2::{
    Pbkdf2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};

use rand::TryRngCore;
use rand_core::OsRng;

use std::collections::HashMap;

pub trait Users {
    fn create_user(&mut self, username: &str, password: &str) -> Result<(), String>;
    fn get_user_uuid(&self, username: &str, password: &str) -> Option<String>;
    fn delete_user(&mut self, user_uuid: String);
}

#[derive(Clone)]
pub struct User {
    user_uuid: String,
    username: String,
    password: String,
}

#[derive(Default)]
pub struct UsersImpl {
    uuid_to_user: HashMap<String, User>,
    username_to_user: HashMap<String, User>,
}

impl Users for UsersImpl {
    fn create_user(&mut self, username: &str, password: &str) -> Result<(), String> {
        let user = self.get_user_uuid(&username, &password);
        if user.is_some() {
            return Err("Username already exists.".to_owned());
        }

        const SALT_LEN: usize = 16;
        let mut salt_bytes = [0u8; SALT_LEN];
        OsRng.try_fill_bytes(&mut salt_bytes).unwrap();

        let salt_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&salt_bytes);
        let salt = SaltString::from_b64(&salt_b64)
            .map_err(|e| format!("Failed to create salt.\n{e:?}"))?;

        let hashed_password = Pbkdf2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| format!("Failed to hash password.\n{e:?}"))?
            .to_string();

        let user = User {
            user_uuid: uuid::Uuid::new_v4().to_string(),
            username: username.to_owned(),
            password: hashed_password,
        };

        // TODO: Add user to `username_to_user` and `uuid_to_user`.
        self.username_to_user
            .insert(username.to_owned(), user.clone());
        self.uuid_to_user.insert(user.user_uuid.clone(), user);

        Ok(())
    }

    fn get_user_uuid(&self, username: &str, password: &str) -> Option<String> {
        //TODO: Retrieve `User` or return `None` is user can't be found.
        let user = self.username_to_user.get(username)?;
        if user.username != username {
            return None;
        }

        // Get user's password as `PasswordHash` instance.
        let hashed_password = user.password.clone();
        let parsed_hash = PasswordHash::new(&hashed_password).ok()?;

        // Verify passed in password matches user's password.
        let result = Pbkdf2.verify_password(password.as_bytes(), &parsed_hash);

        // TODO: If the username and password passed in matches the user's username and password return the user's uuid.
        if result.is_ok() {
            return Some(user.user_uuid.clone());
        }

        None
    }

    fn delete_user(&mut self, user_uuid: String) {
        // TODO: Remove user from `username_to_user` and `uuid_to_user`.
        if let Some(user) = self.uuid_to_user.remove(&user_uuid) {
            println!(
                "Deleting user {} with uuid: {}",
                user.username, user.user_uuid
            );
            self.username_to_user.remove(&user.username);
            return;
        }
        println!("User with uuid: {} not found", user_uuid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_user() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username", "password")
            .expect("should create user");

        assert_eq!(user_service.uuid_to_user.len(), 1);
        assert_eq!(user_service.username_to_user.len(), 1);
    }

    #[test]
    fn should_fail_creating_user_with_existing_username() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username", "password")
            .expect("should create user");

        let result = user_service.create_user("username", "password");

        assert!(result.is_err());
    }

    #[test]
    fn should_retrieve_user_uuid() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username", "password")
            .expect("should create user");

        assert!(user_service.get_user_uuid("username", "password").is_some());
    }

    #[test]
    fn should_fail_to_retrieve_user_uuid_with_incorrect_password() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username", "password")
            .expect("should create user");

        assert!(
            user_service
                .get_user_uuid("username", "incorrect password")
                .is_none()
        );
    }

    #[test]
    fn should_delete_user() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username", "password")
            .expect("should create user");

        let user_uuid = user_service.get_user_uuid("username", "password").unwrap();

        user_service.delete_user(user_uuid);

        assert_eq!(user_service.uuid_to_user.len(), 0);
        assert_eq!(user_service.username_to_user.len(), 0);
    }
}
