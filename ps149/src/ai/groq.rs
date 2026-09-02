use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

const GROQ_API_URL: &str = "https://api.groq.com/openai/v1/chat/completions";
const DEFAULT_MODEL: &str = "llama-3.3-70b-versatile";

/// Groq API client for AI-powered features.
pub struct GroqClient {
    api_key: String,
    client: reqwest::blocking::Client,
    model: String,
}

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
    max_tokens: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChatMessage,
}

impl GroqClient {
    /// Creates a new Groq client from the GROQ_API_KEY environment variable.
    /// Returns None if the key isn't set (AI features disabled gracefully).
    pub fn from_env() -> Option<Self> {
        let api_key = std::env::var("GROQ_API_KEY").ok()?;
        if api_key.is_empty() {
            return None;
        }
        Some(Self {
            api_key,
            client: reqwest::blocking::Client::new(),
            model: DEFAULT_MODEL.to_string(),
        })
    }

    /// Sends a chat completion request to Groq and returns the response text.
    pub fn chat(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: system_prompt.to_string(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: user_prompt.to_string(),
                },
            ],
            temperature: 0.3,
            max_tokens: 1024,
        };

        let response = self
            .client
            .post(GROQ_API_URL)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            bail!("Groq API error {}: {}", status, body);
        }

        let chat_response: ChatResponse = response.json()?;
        chat_response
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .ok_or_else(|| anyhow::anyhow!("Groq returned empty response"))
    }
}
