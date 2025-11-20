# Google Gemini API Setup Guide

## Overview

The pipeline now uses **Google Gemini API** instead of DeepSeek for AI-powered analysis and report generation.

## Getting Your API Key

1. **Visit**: https://aistudio.google.com/app/apikey
2. **Sign in** with your Google account
3. **Create** a new API key
4. **Copy** the API key (format: `AIzaSy...`)

## Adding to .env File

Create or edit `.env` file in the project root:

```env
GEMINI_API_KEY=AIzaSyApbophciO1o3cVsogw5D9gzgSMMZbosq4
VIRUSTOTAL_API_KEY=your_virustotal_key_here
```

## API Usage

The Gemini API is used in:
- **Step 4**: File format analysis
- **Step 6**: String analysis for malicious patterns
- **All Steps**: AI-generated reports for each analysis step

## Model Used

- **Model**: `gemini-1.5-pro`
- **Endpoint**: `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent`

## Rate Limits

Google Gemini API has generous free tier limits:
- **Free tier**: 15 requests per minute (RPM)
- **Free tier**: 1,500 requests per day (RPD)

For higher limits, consider upgrading your Google Cloud account.

## Troubleshooting

### "GEMINI_API_KEY not set"
- Ensure `.env` file exists in project root
- Check that API key is correctly set: `GEMINI_API_KEY=AIzaSy...`
- Restart your terminal/IDE after adding the key

### API Errors
- Check your API key is valid
- Verify you haven't exceeded rate limits
- Ensure your Google account has API access enabled

## Migration from DeepSeek

If you were using DeepSeek API:
1. Get a new Gemini API key from https://aistudio.google.com/app/apikey
2. Replace `DEEPSEEK_API_KEY` with `GEMINI_API_KEY` in your `.env` file
3. The pipeline will automatically use Gemini API

## Benefits of Gemini API

- **Free tier available**: Generous free usage limits
- **High quality**: Advanced AI model for analysis
- **Reliable**: Google's infrastructure
- **No credit card required**: For free tier usage

