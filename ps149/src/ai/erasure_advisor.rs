use super::groq::GroqClient;
use crate::model::PhysicalDisk;
use anyhow::Result;

const SYSTEM_PROMPT: &str = "\
You are a data sanitization expert advising on secure erasure methods. \
Based on the device information provided, recommend the optimal NIST SP 800-88 \
erasure method and explain why. Be concise (under 100 words). \
Mention any limitations of software-based erasure for this device type. \
Format your response as:\n\
RECOMMENDED: [method name]\n\
REASON: [explanation]\n\
LIMITATION: [any caveats]";

/// Gets AI-powered erasure recommendation for a specific device.
pub fn get_recommendation(groq: &GroqClient, disk: &PhysicalDisk) -> Result<String> {
    let user_prompt = format!(
        "Recommend the best erasure method for this device:\n\
         \n\
         Device Type: {}\n\
         Model: {}\n\
         Interface: {}\n\
         Capacity: {}\n\
         Media Type: {}\n\
         Sector Size: {} bytes\n\
         Total Sectors: {}",
        disk.device_type,
        disk.model.as_deref().unwrap_or("Unknown"),
        disk.interface_type.as_deref().unwrap_or("Unknown"),
        disk.capacity_display(),
        disk.media_type.as_deref().unwrap_or("Unknown"),
        disk.bytes_per_sector,
        disk.total_sectors,
    );

    groq.chat(SYSTEM_PROMPT, &user_prompt)
}
