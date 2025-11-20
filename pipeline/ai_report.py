"""
AI Report Generation Module
Generates AI-powered reports for each analysis step using Google Gemini API.
"""
import json
import logging
import os
import re
import time
from typing import Dict, List, Optional

from google import genai
from google.genai import errors

logger = logging.getLogger(__name__)

# Use stable model - gemini-pro is the most widely available
GEMINI_MODEL = "gemini-pro"
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds


def generate_step_report(step_result: Dict, step_number: int, step_name: str) -> Dict:
    """
    Generate AI-powered report for a single analysis step.
    
    Args:
        step_result: Results from the analysis step
        step_number: Step number (1-8)
        step_name: Name of the step
        
    Returns:
        Dictionary with AI-generated report
    """
    logger.info(f"[AI Report] Generating report for Step {step_number}: {step_name}")
    
    result = {
        "step": step_number,
        "step_name": step_name,
        "ai_report": None,
        "error": None
    }
    
    try:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            result["error"] = "GEMINI_API_KEY not set"
            logger.warning(f"[AI Report] GEMINI_API_KEY not set, skipping report for step {step_number}")
            return result
        
        # Initialize Gemini client
        client = genai.Client(api_key=api_key)
        
        # Build combined prompt (all content in single string)
        contents = f"""You are a senior malware analyst. Generate a comprehensive, structured report based on the analysis results provided. Be specific, cite findings, and provide actionable insights.

Analyze the following results from Step {step_number}: {step_name}

Analysis Results:
{json.dumps(step_result, indent=2, ensure_ascii=False)}

Please generate a comprehensive report including:
1. Executive Summary
2. Key Findings
3. Technical Details
4. Risk Assessment
5. Recommendations

Format the report in clear, structured markdown with sections and bullet points.
"""
        
        # Call Gemini API with retry logic
        response = None
        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                response = client.models.generate_content(
                    model=GEMINI_MODEL,
                    contents=contents,
                )
                
                if response and hasattr(response, 'text') and response.text:
                    result["ai_report"] = response.text
                    logger.info(f"[AI Report] Report generated successfully for step {step_number}")
                    break
                else:
                    result["error"] = "No response content from Gemini API"
                    result["ai_report"] = f"# API Error\n\nNo response content from Gemini API.\n\n**Note**: This report could not be generated. Please check your Gemini API key."
                    logger.error(f"[AI Report] No response content for step {step_number}")
                    break
                    
            except errors.ServerError as e:
                last_error = e
                if "overloaded" in str(e).lower() or "503" in str(e):
                    if attempt < MAX_RETRIES - 1:
                        wait_time = RETRY_DELAY * (2 ** attempt)  # Exponential backoff
                        logger.warning(f"[AI Report] Model overloaded (attempt {attempt + 1}/{MAX_RETRIES}), retrying in {wait_time}s...")
                        time.sleep(wait_time)
                        continue
                    else:
                        result["error"] = f"Model overloaded after {MAX_RETRIES} attempts. Please try again later."
                        result["ai_report"] = f"# API Error\n\nModel is currently overloaded. Please try again later.\n\n**Error**: {str(e)}"
                        logger.error(f"[AI Report] Model overloaded after {MAX_RETRIES} attempts for step {step_number}")
                else:
                    result["error"] = str(e)
                    result["ai_report"] = f"# API Error\n\n{str(e)}\n\n**Note**: This report could not be generated due to API issues."
                    logger.error(f"[AI Report] API error for step {step_number}: {e}")
                    break
            except Exception as e:
                last_error = e
                result["error"] = str(e)
                result["ai_report"] = f"# API Error\n\n{str(e)}\n\n**Note**: This report could not be generated due to an unexpected error."
                logger.error(f"[AI Report] Unexpected error for step {step_number}: {e}", exc_info=True)
                break
    
    except Exception as e:
        logger.error(f"[AI Report] Error generating report for step {step_number}: {e}", exc_info=True)
        result["error"] = str(e)
    
    return result

