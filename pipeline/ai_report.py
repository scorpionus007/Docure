"""
AI Report Generation Module
Generates AI-powered reports for each analysis step using Anthropic Claude API.
"""
import json
import logging
import os
import re
import time
from typing import Dict, List, Optional

# Load .env file if present
try:
    from dotenv import load_dotenv  # type: ignore
    import pathlib
    # Try to find .env file in project root (parent of pipeline directory)
    env_path = pathlib.Path(__file__).parent.parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
    else:
        # Fallback to default location (current working directory)
        load_dotenv()
except Exception as e:
    import logging
    logging.getLogger(__name__).debug(f"Could not load .env file: {e}")
    pass

from anthropic import Anthropic
try:
    from anthropic import APIError
except ImportError:
    # Fallback if APIError doesn't exist
    APIError = Exception

logger = logging.getLogger(__name__)

# Use Claude model - try haiku first (most widely available), fallback to others if needed
# Available models: "claude-3-haiku-20240307", "claude-3-sonnet-20240229", "claude-3-opus-20240229"
CLAUDE_MODEL = "claude-3-haiku-20240307"
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
        # Try loading .env again just before checking (in case it wasn't loaded during import)
        try:
            from dotenv import load_dotenv  # type: ignore
            import pathlib
            env_path = pathlib.Path(__file__).parent.parent / ".env"
            if env_path.exists():
                load_dotenv(dotenv_path=env_path, override=True)
                logger.debug(f"[AI Report] Loaded .env from: {env_path}")
            else:
                load_dotenv(override=True)
                logger.debug(f"[AI Report] Loaded .env from current directory")
        except Exception as e:
            logger.debug(f"[AI Report] Could not reload .env: {e}")
        
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            result["error"] = "ANTHROPIC_API_KEY not set"
            logger.warning(f"[AI Report] ANTHROPIC_API_KEY not set, skipping report for step {step_number}")
            logger.warning(f"[AI Report] Make sure .env file exists in project root with: ANTHROPIC_API_KEY=your_key")
            # Check if .env file exists
            import pathlib
            env_path = pathlib.Path(__file__).parent.parent / ".env"
            if env_path.exists():
                logger.warning(f"[AI Report] .env file found at {env_path}, but ANTHROPIC_API_KEY is not set in it")
            else:
                logger.warning(f"[AI Report] .env file not found at {env_path}")
            return result
        
        # Log that API key was found (but don't log the actual key)
        logger.info(f"[AI Report] API key found, generating report for step {step_number}")
        
        # Initialize Anthropic Claude client
        client = Anthropic(api_key=api_key)
        
        # Build system and user messages
        system_message = "You are a senior malware analyst. Generate a comprehensive, structured report based on the analysis results provided. Be specific, cite findings, and provide actionable insights. Explain WHY and HOW things are happening in detail."
        
        user_message = f"""Analyze the following results from Step {step_number}: {step_name}

Analysis Results:
{json.dumps(step_result, indent=2, ensure_ascii=False)}

Please generate a comprehensive report including:
1. Executive Summary - Brief overview of findings
2. Key Findings - What was discovered and why it matters
3. Technical Details - HOW things work, step-by-step explanations
4. Risk Assessment - WHY these findings are concerning
5. Recommendations - Actionable next steps

Format the report in clear, structured markdown with sections and bullet points. Be detailed and explain the reasoning behind each finding.
"""
        
        # Call Claude API with retry logic
        response = None
        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                logger.debug(f"[AI Report] Calling Claude API for step {step_number} (attempt {attempt + 1}/{MAX_RETRIES})")
                response = client.messages.create(
                    model=CLAUDE_MODEL,
                    max_tokens=4096,
                    system=system_message,
                    messages=[{"role": "user", "content": user_message}],
                )
                
                logger.debug(f"[AI Report] API response received for step {step_number}")
                logger.debug(f"[AI Report] Response type: {type(response)}")
                logger.debug(f"[AI Report] Has content attr: {hasattr(response, 'content')}")
                
                if response and hasattr(response, 'content'):
                    logger.debug(f"[AI Report] Response.content type: {type(response.content)}")
                    logger.debug(f"[AI Report] Response.content value: {response.content}")
                    
                    if response.content:
                        # Extract text from response content (list of content blocks)
                        content_blocks = response.content
                        content = ""
                        logger.debug(f"[AI Report] Processing {len(content_blocks)} content blocks")
                        
                        for i, block in enumerate(content_blocks):
                            logger.debug(f"[AI Report] Block {i} type: {type(block)}")
                            if hasattr(block, 'text'):
                                block_text = block.text
                                logger.debug(f"[AI Report] Block {i} has text attribute, length: {len(block_text) if block_text else 0}")
                                content += block_text
                            elif isinstance(block, dict) and block.get('type') == 'text':
                                block_text = block.get('text', '')
                                logger.debug(f"[AI Report] Block {i} is dict with text, length: {len(block_text) if block_text else 0}")
                                content += block_text
                            else:
                                logger.warning(f"[AI Report] Block {i} has unexpected format: {block}")
                        
                        if content:
                            result["ai_report"] = content
                            logger.info(f"[AI Report] Report generated successfully for step {step_number} (length: {len(content)} chars)")
                            break
                        else:
                            result["error"] = "Response content blocks were empty"
                            result["ai_report"] = f"# API Error\n\nResponse received but content blocks were empty.\n\n**Note**: This report could not be generated."
                            logger.error(f"[AI Report] Content blocks were empty for step {step_number}")
                            break
                    else:
                        result["error"] = "No response content from Claude API (response.content is empty)"
                        result["ai_report"] = f"# API Error\n\nNo response content from Claude API.\n\n**Note**: This report could not be generated. Please check your Anthropic API key."
                        logger.error(f"[AI Report] No response content for step {step_number} - response.content is empty or None")
                        break
                else:
                    result["error"] = f"No response or missing content attribute. Response type: {type(response)}"
                    result["ai_report"] = f"# API Error\n\nInvalid response format from Claude API.\n\n**Note**: This report could not be generated."
                    logger.error(f"[AI Report] Invalid response for step {step_number}: {response}")
                    break
                    
            except APIError as e:
                last_error = e
                status_code = getattr(e, 'status_code', None)
                error_message = str(e)
                logger.error(f"[AI Report] APIError for step {step_number} (attempt {attempt + 1}): {error_message} (status_code: {status_code})")
                
                if status_code == 503 or "overloaded" in error_message.lower() or status_code == 429:
                    if attempt < MAX_RETRIES - 1:
                        wait_time = RETRY_DELAY * (2 ** attempt)  # Exponential backoff
                        logger.warning(f"[AI Report] Model overloaded (attempt {attempt + 1}/{MAX_RETRIES}), retrying in {wait_time}s...")
                        time.sleep(wait_time)
                        continue
                    else:
                        result["error"] = f"Model overloaded after {MAX_RETRIES} attempts. Please try again later."
                        result["ai_report"] = f"# API Error\n\nModel is currently overloaded. Please try again later.\n\n**Error**: {error_message}"
                        logger.error(f"[AI Report] Model overloaded after {MAX_RETRIES} attempts for step {step_number}")
                else:
                    result["error"] = error_message
                    result["ai_report"] = f"# API Error\n\n{error_message}\n\n**Note**: This report could not be generated due to API issues."
                    logger.error(f"[AI Report] API error for step {step_number}: {error_message} (status_code: {status_code})")
                    break
            except Exception as e:
                last_error = e
                error_message = str(e)
                error_type = type(e).__name__
                logger.error(f"[AI Report] Unexpected error for step {step_number} (attempt {attempt + 1}): {error_type}: {error_message}", exc_info=True)
                result["error"] = f"{error_type}: {error_message}"
                result["ai_report"] = f"# API Error\n\n{error_type}: {error_message}\n\n**Note**: This report could not be generated due to an unexpected error."
                # Don't break on first attempt for unexpected errors, try retrying
                if attempt < MAX_RETRIES - 1:
                    wait_time = RETRY_DELAY * (2 ** attempt)
                    logger.warning(f"[AI Report] Retrying after unexpected error in {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                else:
                    break
    
    except Exception as e:
        logger.error(f"[AI Report] Error generating report for step {step_number}: {e}", exc_info=True)
        result["error"] = str(e)
    
    return result


def generate_summary_report(complete_analysis: Dict) -> Dict:
    """
    Generate a comprehensive AI-powered summary report from the complete analysis results.
    
    Args:
        complete_analysis: Complete analysis results dictionary from the pipeline
        
    Returns:
        Dictionary with AI-generated summary report
    """
    logger.info("[AI Report] Generating comprehensive summary report")
    
    result = {
        "summary_report": None,
        "error": None
    }
    
    try:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            result["error"] = "ANTHROPIC_API_KEY not set"
            logger.warning("[AI Report] ANTHROPIC_API_KEY not set, skipping summary report generation")
            return result
        
        # Log that API key was found
        logger.info("[AI Report] API key found, generating comprehensive summary report")
        
        # Initialize Anthropic Claude client
        client = Anthropic(api_key=api_key)
        
        # Extract key information from all steps
        file_name = complete_analysis.get("file_name", "unknown")
        file_path = complete_analysis.get("file_path", "unknown")
        summary = complete_analysis.get("summary", {})
        steps = complete_analysis.get("steps", [])
        errors = complete_analysis.get("errors", [])
        
        # Build comprehensive summary data
        summary_data = {
            "file_info": {
                "file_name": file_name,
                "file_path": file_path,
                "total_steps": summary.get("total_steps", 0),
                "completed_steps": summary.get("completed_steps", 0),
                "errors_count": summary.get("errors", 0),
                "is_packed": summary.get("is_packed", False),
                "has_hash": summary.get("has_hash", False),
                "has_signature_info": summary.get("has_signature_info", False)
            },
            "step_summaries": []
        }
        
        # Extract key findings from each step
        for step in steps:
            step_num = step.get("step")
            step_name = step.get("step_name", "Unknown Step")
            step_summary = {
                "step": step_num,
                "step_name": step_name,
                "key_findings": {}
            }
            
            # Extract key findings based on step type
            if step_num == 1:  # Packing
                step_summary["key_findings"] = {
                    "is_packed": step.get("is_packed", False),
                    "packer_type": step.get("packer_type"),
                    "entropy": step.get("entropy"),
                    "unpacked_success": step.get("unpacked", {}).get("success", False)
                }
            elif step_num == 2:  # Hash
                step_summary["key_findings"] = {
                    "hashes": step.get("hashes", {}),
                    "method": step.get("method")
                }
            elif step_num == 3:  # Resources
                step_summary["key_findings"] = {
                    "resource_count": step.get("resource_count", 0),
                    "error": step.get("error")
                }
            elif step_num == 4:  # Format
                step_summary["key_findings"] = {
                    "actual_format": step.get("actual_format"),
                    "is_pe": step.get("is_pe_executable", False),
                    "format_match": step.get("format_match", False)
                }
            elif step_num == 5:  # Imports
                step_summary["key_findings"] = {
                    "import_count": step.get("import_count", 0),
                    "export_count": step.get("export_count", 0),
                    "suspicious_imports": step.get("suspicious_imports", [])
                }
            elif step_num == 6:  # Strings
                step_summary["key_findings"] = {
                    "strings_count": step.get("strings_count", 0),
                    "malicious_patterns_count": len(step.get("malicious_patterns", [])),
                    "suspicious_strings_count": len(step.get("suspicious_strings", [])),
                    "iocs": step.get("iocs", {})
                }
            elif step_num == 7:  # Signature
                step_summary["key_findings"] = {
                    "signed": step.get("signature_info", {}).get("signed", False),
                    "reputation": step.get("reputation", {}),
                    "permalink": step.get("permalink")
                }
            elif step_num == 8:  # Metadata
                step_summary["key_findings"] = {
                    "file_size": step.get("metadata", {}).get("file_size"),
                    "file_type": step.get("metadata", {}).get("file_type"),
                    "created_time": step.get("metadata", {}).get("created_time")
                }
            
            summary_data["step_summaries"].append(step_summary)
        
        # Build system and user messages
        system_message = """You are a senior malware analyst. Generate a comprehensive, executive-level summary report that consolidates findings from all 8 analysis steps. 
        
The report should:
1. Provide a high-level executive summary that gives decision-makers a clear understanding of the threat
2. Synthesize findings from all steps to identify patterns and correlations
3. Highlight the most critical security concerns
4. Provide actionable recommendations based on the complete analysis
5. Explain the overall risk level and why it matters

Be concise but thorough, focusing on the most important findings that would help security teams make informed decisions."""
        
        user_message = f"""Analyze the complete malware analysis results for file: {file_name}

Complete Analysis Summary:
{json.dumps(summary_data, indent=2, ensure_ascii=False)}

All Step Results:
{json.dumps(steps, indent=2, ensure_ascii=False)}

Errors Encountered:
{json.dumps(errors, indent=2, ensure_ascii=False) if errors else "No errors"}

Please generate a comprehensive executive summary report that:
1. **Executive Summary** - High-level overview of the file, overall risk assessment, and key decision points
2. **Consolidated Findings** - Synthesize findings from all 8 steps, highlighting patterns and correlations
3. **Critical Security Concerns** - Identify the most serious threats and why they matter
4. **Risk Assessment** - Overall risk level (Low/Medium/High/Critical) with detailed justification
5. **Actionable Recommendations** - Prioritized list of actions based on all findings
6. **Step-by-Step Summary** - Brief summary of key findings from each of the 8 steps
7. **Conclusion** - Final assessment and next steps

Format the report in clear, structured markdown with sections, subsections, and bullet points. Be detailed but accessible to both technical and non-technical audiences."""
        
        # Call Claude API with retry logic
        response = None
        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                logger.debug(f"[AI Report] Calling Claude API for summary report (attempt {attempt + 1}/{MAX_RETRIES})")
                response = client.messages.create(
                    model=CLAUDE_MODEL,
                    max_tokens=4096,  # Maximum allowed for Claude 3 Haiku
                    system=system_message,
                    messages=[{"role": "user", "content": user_message}],
                )
                
                logger.debug(f"[AI Report] API response received for summary report")
                
                if response and hasattr(response, 'content') and response.content:
                    # Extract text from response content
                    content_blocks = response.content
                    content = ""
                    for block in content_blocks:
                        if hasattr(block, 'text'):
                            content += block.text
                        elif isinstance(block, dict) and block.get('type') == 'text':
                            content += block.get('text', '')
                    
                    if content:
                        result["summary_report"] = content
                        logger.info(f"[AI Report] Summary report generated successfully (length: {len(content)} chars)")
                        break
                    else:
                        result["error"] = "Response content blocks were empty"
                        logger.error("[AI Report] Content blocks were empty for summary report")
                        break
                else:
                    result["error"] = "No response content from Claude API"
                    logger.error("[AI Report] No response content for summary report")
                    break
                    
            except APIError as e:
                last_error = e
                status_code = getattr(e, 'status_code', None)
                error_message = str(e)
                
                # Check for max_tokens error and provide helpful message
                if "max_tokens" in error_message.lower() or status_code == 400:
                    result["error"] = f"API Error: {error_message}. The model has token limits. Try using a different model or reducing the input size."
                    logger.error(f"[AI Report] Token limit error for summary report: {error_message}")
                    break
                elif status_code == 503 or "overloaded" in error_message.lower() or status_code == 429:
                    if attempt < MAX_RETRIES - 1:
                        wait_time = RETRY_DELAY * (2 ** attempt)
                        logger.warning(f"[AI Report] Model overloaded (attempt {attempt + 1}/{MAX_RETRIES}), retrying in {wait_time}s...")
                        time.sleep(wait_time)
                        continue
                    else:
                        result["error"] = f"Model overloaded after {MAX_RETRIES} attempts. Please try again later."
                        logger.error(f"[AI Report] Model overloaded after {MAX_RETRIES} attempts for summary report")
                else:
                    result["error"] = error_message
                    logger.error(f"[AI Report] API error for summary report: {error_message} (status_code: {status_code})")
                    break
            except Exception as e:
                last_error = e
                error_message = str(e)
                error_type = type(e).__name__
                logger.error(f"[AI Report] Unexpected error for summary report (attempt {attempt + 1}): {error_type}: {error_message}", exc_info=True)
                if attempt < MAX_RETRIES - 1:
                    wait_time = RETRY_DELAY * (2 ** attempt)
                    time.sleep(wait_time)
                    continue
                else:
                    result["error"] = f"{error_type}: {error_message}"
                    break
    
    except Exception as e:
        logger.error(f"[AI Report] Error generating summary report: {e}", exc_info=True)
        result["error"] = str(e)
    
    return result

