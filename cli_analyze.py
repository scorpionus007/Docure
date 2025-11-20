import argparse
import json
import logging
import os
import sys
from datetime import datetime

# Load .env if present
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

from pipeline.pipeline_8step import run_8step_pipeline


def setup_logging(output_dir: str, verbose: bool = False):
    """Setup comprehensive logging for the analysis pipeline."""
    log_dir = os.path.join(output_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    # Configure logging
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized. Log file: {log_file}")
    return logger


def main():
    p = argparse.ArgumentParser(
        description="8-Step Static Malware Analysis Pipeline - Analyzes .exe files with comprehensive static analysis"
    )
    p.add_argument("--file", required=True, help="Path to the .exe malware sample to analyze")
    p.add_argument("--out", default="outputs", help="Output directory for analysis results")
    p.add_argument("--no-ai-reports", action="store_true", help="Disable AI-generated reports for each step")
    p.add_argument("--verbose", action="store_true", help="Enable verbose debug logging")
    args = p.parse_args()

    # Setup logging
    logger = setup_logging(args.out, args.verbose)
    
    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)

    try:
        logger.info("=" * 80)
        logger.info("Starting 8-Step Static Malware Analysis Pipeline")
        logger.info("=" * 80)
        logger.info(f"Input file: {args.file}")
        logger.info(f"Output directory: {out_dir}")
        logger.info(f"AI Reports: {not args.no_ai_reports}")
        
        if not os.path.isfile(args.file):
            logger.error(f"File not found: {args.file}")
            print(f"Error: File not found: {args.file}")
            return 1
        
        # Run the 8-step pipeline
        results = run_8step_pipeline(
            file_path=args.file,
            output_dir=out_dir,
            use_ai_reports=not args.no_ai_reports
        )
        
        # Print summary
        summary = results.get("summary", {})
        logger.info("=" * 80)
        logger.info("Analysis Pipeline Summary")
        logger.info("=" * 80)
        logger.info(f"Completed Steps: {summary.get('completed_steps', 0)}/8")
        logger.info(f"Errors: {summary.get('errors', 0)}")
        logger.info(f"File Packed: {summary.get('is_packed', False)}")
        logger.info(f"Results saved to: {out_dir}")
        logger.info("=" * 80)
        
        print("\n" + "=" * 80)
        print("Analysis Complete!")
        print("=" * 80)
        print(f"Completed Steps: {summary.get('completed_steps', 0)}/8")
        print(f"Results directory: {out_dir}")
        print(f"  - Step results: {out_dir}/steps/")
        print(f"  - Step reports: {out_dir}/steps/*_report.md")
        print(f"  - Complete analysis: {out_dir}/complete_analysis.json")
        print(f"  - Logs: {out_dir}/logs/")
        print("=" * 80)
        
    except Exception as e:
        logger.error(f"Pipeline execution failed: {e}", exc_info=True)
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())


