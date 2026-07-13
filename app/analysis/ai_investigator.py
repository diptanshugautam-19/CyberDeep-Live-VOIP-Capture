import os
import json
import httpx
import logging
from typing import Dict, Any, List, Optional
from app.storage.database import router

logger = logging.getLogger("ai-investigator")

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
MODEL_NAME = "llama-3.3-70b-versatile"

class AIInvestigator:
    @staticmethod
    async def chat_investigate(session_id: str, message: str) -> Dict[str, Any]:
        logger.info(f"AI Investigation requested for session {session_id} with query: {message}")
        
        # 1. Fetch the InvestigationSession from the DB
        db_path = router.table_map["investigations"]
        rows = router.execute("investigations", "SELECT case_json FROM investigations WHERE id = ?", (session_id,))
        if not rows:
            return {
                "text": "Investigation session not found in the database. Please analyze a PCAP file first.",
                "citations": []
            }
        
        case_data = json.loads(rows[0]["case_json"])
        
        # Build compact context for LLM injection
        context = {
            "session_id": session_id,
            "sip_calls": case_data.get("sip_calls", []),
            "rtp_sessions": case_data.get("rtp_sessions", []),
            "ice_sessions": case_data.get("ice_sessions", []),
            "stun_transactions": case_data.get("stun_transactions", [])[:50],  # Limit to save token space
            "endpoints": case_data.get("endpoints", [])[:30],
            "conversations": case_data.get("conversations", [])[:30],
            "timeline_sample": case_data.get("timeline", [])[:100]  # First 100 packets
        }

        # Build valid list of packet and session IDs to cross-verify citations
        valid_packet_ids = {f"p_{p['packet_index']}" for p in case_data.get("timeline", [])}
        valid_packet_ids.update({str(p['packet_index']) for p in case_data.get("timeline", [])})
        valid_session_ids = {session_id}
        for s in case_data.get("sip_calls", []):
            valid_session_ids.add(s.get("call_id"))
        for r in case_data.get("rtp_sessions", []):
            valid_session_ids.add(r.get("ssrc"))

        system_prompt = (
            "You are an expert digital forensics AI investigator specializing in VoIP analysis.\n"
            "You are given structured telemetry of a packet capture session including SIP calls, RTP sessions, ICE states, and a packet timeline.\n"
            "Analyze the given session and answer the user's question.\n"
            "CRITICAL: You MUST respond ONLY with a raw JSON object containing two fields:\n"
            "1. 'text': Your analytical response in markdown format. Explain clearly what you found.\n"
            "2. 'citations': A list of citation objects. Each citation must have:\n"
            "   - 'claim': The specific statement or claim made in the text.\n"
            "   - 'packet_ids': A list of string packet IDs (e.g. 'p_1', 'p_2') or session IDs (e.g. Call-IDs or SSRCs) backing this claim.\n"
            "Only cite packet/session IDs that exist in the provided context data. Do not hallucinate packet IDs.\n"
            "Example output format:\n"
            "{\n"
            "  \"text\": \"The SIP INVITE request was sent from 192.168.1.5 to 192.168.1.10.\",\n"
            "  \"citations\": [\n"
            "    {\"claim\": \"SIP INVITE request from 192.168.1.5\", \"packet_ids\": [\"p_1\"]}\n"
            "  ]\n"
            "}"
        )

        user_content = f"CONTEXT DATA:\n{json.dumps(context, indent=2)}\n\nUSER QUESTION: {message}"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GROQ_API_KEY}"
        }
        
        payload = {
            "model": MODEL_NAME,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"}
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.post(GROQ_API_URL, headers=headers, json=payload)
                resp.raise_for_status()
                result = resp.json()
                
                content = result["choices"][0]["message"]["content"]
                parsed_response = json.loads(content)
                
                # Validate citations
                validated_citations = []
                for cit in parsed_response.get("citations", []):
                    claim = cit.get("claim", "")
                    p_ids = cit.get("packet_ids", [])
                    # Only keep existing packet/session IDs
                    valid_ids = [pid for pid in p_ids if str(pid) in valid_packet_ids or str(pid) in valid_session_ids]
                    if valid_ids:
                        validated_citations.append({
                            "claim": claim,
                            "packet_ids": valid_ids
                        })
                
                parsed_response["citations"] = validated_citations
                return parsed_response

            except Exception as e:
                logger.error(f"Error querying Groq API: {e}")
                return {
                    "text": f"Error querying Groq AI Model: {str(e)}",
                    "citations": []
                }
