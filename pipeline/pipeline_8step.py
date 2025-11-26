"""
8-Step Static Malware Analysis Pipeline
Sequential execution of all analysis steps with AI-powered reporting.
"""
import json
import logging
import os
from typing import Dict, List, Optional

from .step1_packing import analyze_packing
from .step2_hash import analyze_hash
from .step3_resources import analyze_resources
from .step4_format import analyze_format
from .step5_imports import analyze_imports_exports
from .step6_strings import analyze_strings
from .step7_signature import check_signature_virustotal
from .step8_metadata import extract_metadata
from .ai_report import generate_step_report, generate_summary_report
from .ai_report import generate_step_report

logger = logging.getLogger(__name__)


def run_8step_pipeline(
    file_path: str,
    output_dir: str,
    use_ai_reports: bool = True,
    unpack_output_dir: Optional[str] = None
) -> Dict:
    """
    Run the complete 8-step static malware analysis pipeline.
    
    Args:
        file_path: Path to the malware sample (.exe file)
        output_dir: Directory to store analysis results
        use_ai_reports: Whether to generate AI reports for each step
        unpack_output_dir: Directory for unpacked files (if None, uses output_dir/unpacked)
        
    Returns:
        Dictionary with complete analysis results
    """
    logger.info(f"[Pipeline] Starting 8-step analysis pipeline for: {file_path}")
    
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    os.makedirs(output_dir, exist_ok=True)
    
    if unpack_output_dir is None:
        unpack_output_dir = os.path.join(output_dir, "unpacked")
    os.makedirs(unpack_output_dir, exist_ok=True)
    
    # Create step directories
    steps_dir = os.path.join(output_dir, "steps")
    os.makedirs(steps_dir, exist_ok=True)
    
    results = {
        "file_path": file_path,
        "file_name": os.path.basename(file_path),
        "steps": [],
        "summary": {},
        "errors": []
    }
    
    # Determine file format for Step 4
    apparent_format = os.path.splitext(file_path)[1] or "Unknown"
    file_size = os.path.getsize(file_path)
    
    # Step 1: Packing Detection & Unpacking
    logger.info("=" * 80)
    logger.info("[Pipeline] STEP 1: Packing Detection & Unpacking")
    logger.info("=" * 80)
    try:
        step1_result = analyze_packing(file_path, unpack_output_dir)
        results["steps"].append(step1_result)
        
        # Save step result
        with open(os.path.join(steps_dir, "step1_packing.json"), "w", encoding="utf-8") as f:
            json.dump(step1_result, f, indent=2, ensure_ascii=False)
        
        # Generate AI report
        if use_ai_reports:
            step1_report = generate_step_report(step1_result, 1, "Packing Detection & Unpacking")
            step1_result["ai_report"] = step1_report.get("ai_report")
            report_content = step1_report.get("ai_report") or step1_report.get("error") or "Report generation failed - API error or insufficient balance"
            with open(os.path.join(steps_dir, "step1_report.md"), "w", encoding="utf-8") as f:
                f.write(f"# Step 1: Packing Detection & Unpacking Report\n\n{report_content}")
        
        # Use unpacked file for subsequent steps if available
        analysis_file = file_path
        if step1_result.get("unpacked", {}).get("success"):
            unpacked_path = step1_result["unpacked"]["unpacked_path"]
            if unpacked_path and os.path.isfile(unpacked_path):
                analysis_file = unpacked_path
                logger.info(f"[Pipeline] Using unpacked file for analysis: {unpacked_path}")
    except Exception as e:
        logger.error(f"[Pipeline] Step 1 failed: {e}", exc_info=True)
        results["errors"].append({"step": 1, "error": str(e)})
        analysis_file = file_path
    
    # Step 2: File Hash Calculation
    logger.info("=" * 80)
    logger.info("[Pipeline] STEP 2: File Hash Calculation")
    logger.info("=" * 80)
    try:
        step2_result = analyze_hash(analysis_file)
        results["steps"].append(step2_result)
        
        with open(os.path.join(steps_dir, "step2_hash.json"), "w", encoding="utf-8") as f:
            json.dump(step2_result, f, indent=2, ensure_ascii=False)
        
        if use_ai_reports:
            step2_report = generate_step_report(step2_result, 2, "File Hash Calculation")
            step2_result["ai_report"] = step2_report.get("ai_report")
            report_content = step2_report.get("ai_report") or step2_report.get("error") or "Report generation failed - API error or insufficient balance"
            with open(os.path.join(steps_dir, "step2_report.md"), "w", encoding="utf-8") as f:
                f.write(f"# Step 2: File Hash Calculation Report\n\n{report_content}")
        
        # Get hash for Step 7
        file_hash = step2_result.get("hashes", {}).get("sha256")
        if not file_hash:
            # Try alternative hash locations
            file_hash = step2_result.get("sha256") or (step2_result.get("hashes") or {}).get("SHA256")
    except Exception as e:
        logger.error(f"[Pipeline] Step 2 failed: {e}", exc_info=True)
        results["errors"].append({"step": 2, "error": str(e)})
        file_hash = None
    
    # Step 3: Resource Analysis
    logger.info("=" * 80)
    logger.info("[Pipeline] STEP 3: Resource Analysis")
    logger.info("=" * 80)
    try:
        step3_result = analyze_resources(analysis_file)
        results["steps"].append(step3_result)
        
        with open(os.path.join(steps_dir, "step3_resources.json"), "w", encoding="utf-8") as f:
            json.dump(step3_result, f, indent=2, ensure_ascii=False)
        
        if use_ai_reports:
            step3_report = generate_step_report(step3_result, 3, "Resource Analysis")
            step3_result["ai_report"] = step3_report.get("ai_report")
            report_content = step3_report.get("ai_report") or step3_report.get("error") or "Report generation failed - API error or insufficient balance"
            with open(os.path.join(steps_dir, "step3_report.md"), "w", encoding="utf-8") as f:
                f.write(f"# Step 3: Resource Analysis Report\n\n{report_content}")
    except Exception as e:
        logger.error(f"[Pipeline] Step 3 failed: {e}", exc_info=True)
        results["errors"].append({"step": 3, "error": str(e)})
    
    # Step 4: AI File Format Analysis
    logger.info("=" * 80)
    logger.info("[Pipeline] STEP 4: File Format Detection")
    logger.info("=" * 80)
    try:
        step4_result = analyze_format(analysis_file)
        results["steps"].append(step4_result)
        
        with open(os.path.join(steps_dir, "step4_format.json"), "w", encoding="utf-8") as f:
            json.dump(step4_result, f, indent=2, ensure_ascii=False)
        
        # No AI report for Step 4 - just tool-based format detection
        logger.info(f"[Pipeline] Step 4 completed: File type={step4_result.get('actual_format')}, is_exe={step4_result.get('is_exe')}")
    except Exception as e:
        logger.error(f"[Pipeline] Step 4 failed: {e}", exc_info=True)
        results["errors"].append({"step": 4, "error": str(e)})
    
    # Step 5: Import/Export Analysis
    logger.info("=" * 80)
    logger.info("[Pipeline] STEP 5: Import/Export Analysis")
    logger.info("=" * 80)
    try:
        step5_result = analyze_imports_exports(analysis_file)
        results["steps"].append(step5_result)
        
        with open(os.path.join(steps_dir, "step5_imports.json"), "w", encoding="utf-8") as f:
            json.dump(step5_result, f, indent=2, ensure_ascii=False)
        
        if use_ai_reports:
            step5_report = generate_step_report(step5_result, 5, "Import/Export Analysis")
            step5_result["ai_report"] = step5_report.get("ai_report")
            report_content = step5_report.get("ai_report") or step5_report.get("error") or "Report generation failed - API error or insufficient balance"
            with open(os.path.join(steps_dir, "step5_report.md"), "w", encoding="utf-8") as f:
                f.write(f"# Step 5: Import/Export Analysis Report\n\n{report_content}")
    except Exception as e:
        logger.error(f"[Pipeline] Step 5 failed: {e}", exc_info=True)
        results["errors"].append({"step": 5, "error": str(e)})
    
    # Step 6: String Extraction & AI Analysis
    logger.info("=" * 80)
    logger.info("[Pipeline] STEP 6: String Extraction & AI Analysis")
    logger.info("=" * 80)
    try:
        step6_result = analyze_strings(analysis_file)
        results["steps"].append(step6_result)
        
        with open(os.path.join(steps_dir, "step6_strings.json"), "w", encoding="utf-8") as f:
            json.dump(step6_result, f, indent=2, ensure_ascii=False)
        
        if use_ai_reports:
            step6_report = generate_step_report(step6_result, 6, "String Extraction & AI Analysis")
            step6_result["ai_report"] = step6_report.get("ai_report")
            report_content = step6_report.get("ai_report") or step6_report.get("error") or "Report generation failed - API error or insufficient balance"
            with open(os.path.join(steps_dir, "step6_report.md"), "w", encoding="utf-8") as f:
                f.write(f"# Step 6: String Extraction & AI Analysis Report\n\n{report_content}")
    except Exception as e:
        logger.error(f"[Pipeline] Step 6 failed: {e}", exc_info=True)
        results["errors"].append({"step": 6, "error": str(e)})
    
    # Step 7: Digital Signature Checking (requires hash from Step 2)
    logger.info("=" * 80)
    logger.info("[Pipeline] STEP 7: Digital Signature Checking")
    logger.info("=" * 80)
    try:
        if file_hash:
            step7_result = check_signature_virustotal(file_hash)
            results["steps"].append(step7_result)
            
            with open(os.path.join(steps_dir, "step7_signature.json"), "w", encoding="utf-8") as f:
                json.dump(step7_result, f, indent=2, ensure_ascii=False)
            
            if use_ai_reports:
                step7_report = generate_step_report(step7_result, 7, "Digital Signature Checking")
                step7_result["ai_report"] = step7_report.get("ai_report")
                report_content = step7_report.get("ai_report") or step7_report.get("error") or "Report generation failed - API error or insufficient balance"
                with open(os.path.join(steps_dir, "step7_report.md"), "w", encoding="utf-8") as f:
                    f.write(f"# Step 7: Digital Signature Checking Report\n\n{report_content}")
        else:
            logger.warning("[Pipeline] Step 7 skipped: No hash available from Step 2")
            # Try to get hash from results if step2 completed
            if results["steps"]:
                for step in results["steps"]:
                    if step.get("step") == 2:
                        file_hash = step.get("hashes", {}).get("sha256")
                        if file_hash:
                            logger.info(f"[Pipeline] Found hash in Step 2 results, retrying Step 7")
                            try:
                                step7_result = check_signature_virustotal(file_hash)
                                results["steps"].append(step7_result)
                                with open(os.path.join(steps_dir, "step7_signature.json"), "w", encoding="utf-8") as f:
                                    json.dump(step7_result, f, indent=2, ensure_ascii=False)
                                if use_ai_reports:
                                    step7_report = generate_step_report(step7_result, 7, "Digital Signature Checking")
                                    step7_result["ai_report"] = step7_report.get("ai_report")
                                    report_content = step7_report.get("ai_report") or step7_report.get("error") or "Report generation failed - API error or insufficient balance"
                                    with open(os.path.join(steps_dir, "step7_report.md"), "w", encoding="utf-8") as f:
                                        f.write(f"# Step 7: Digital Signature Checking Report\n\n{report_content}")
                                break
                            except Exception as e:
                                logger.error(f"[Pipeline] Step 7 retry failed: {e}")
            if not any(s.get("step") == 7 for s in results["steps"]):
                results["errors"].append({"step": 7, "error": "No hash available"})
    except Exception as e:
        logger.error(f"[Pipeline] Step 7 failed: {e}", exc_info=True)
        results["errors"].append({"step": 7, "error": str(e)})
    
    # Step 8: Metadata Extraction
    logger.info("=" * 80)
    logger.info("[Pipeline] STEP 8: Metadata Extraction")
    logger.info("=" * 80)
    try:
        step8_result = extract_metadata(analysis_file)
        results["steps"].append(step8_result)
        
        with open(os.path.join(steps_dir, "step8_metadata.json"), "w", encoding="utf-8") as f:
            json.dump(step8_result, f, indent=2, ensure_ascii=False)
        
        if use_ai_reports:
            step8_report = generate_step_report(step8_result, 8, "Metadata Extraction")
            step8_result["ai_report"] = step8_report.get("ai_report")
            report_content = step8_report.get("ai_report") or step8_report.get("error") or "Report generation failed - API error or insufficient balance"
            with open(os.path.join(steps_dir, "step8_report.md"), "w", encoding="utf-8") as f:
                f.write(f"# Step 8: Metadata Extraction Report\n\n{report_content}")
    except Exception as e:
        logger.error(f"[Pipeline] Step 8 failed: {e}", exc_info=True)
        results["errors"].append({"step": 8, "error": str(e)})
    
    # Generate summary
    results["summary"] = {
        "total_steps": 8,
        "completed_steps": len(results["steps"]),
        "errors": len(results["errors"]),
        "is_packed": results["steps"][0].get("is_packed", False) if results["steps"] else False,
        "has_hash": bool(file_hash),
        "has_signature_info": any(
            step.get("step") == 7 and step.get("signature_info") 
            for step in results["steps"]
        )
    }
    
    # Save complete results
    with open(os.path.join(output_dir, "complete_analysis.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # Generate comprehensive summary report
    if use_ai_reports:
        logger.info("=" * 80)
        logger.info("[Pipeline] Generating comprehensive summary report...")
        logger.info("=" * 80)
        try:
            summary_report = generate_summary_report(results)
            summary_content = summary_report.get("summary_report") or summary_report.get("error") or "Summary report generation failed"
            
            # Save summary report
            summary_path = os.path.join(output_dir, "analysis_summary.md")
            with open(summary_path, "w", encoding="utf-8") as f:
                f.write(f"# Comprehensive Malware Analysis Summary Report\n\n")
                f.write(f"**File:** {results.get('file_name', 'unknown')}\n\n")
                f.write(f"**Analysis Date:** {results.get('summary', {}).get('completed_steps', 0)}/8 steps completed\n\n")
                f.write("---\n\n")
                f.write(summary_content)
            
            logger.info(f"[Pipeline] Summary report saved to: {summary_path}")
            results["summary_report_path"] = summary_path
        except Exception as e:
            logger.error(f"[Pipeline] Error generating summary report: {e}", exc_info=True)
            results["summary_report_error"] = str(e)
    
    logger.info("=" * 80)
    logger.info(f"[Pipeline] Analysis pipeline completed: {results['summary']['completed_steps']}/8 steps")
    logger.info("=" * 80)
    
    return results

