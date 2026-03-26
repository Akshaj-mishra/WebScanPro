import os
import json
import datetime
import google.generativeai as genai
from dotenv import load_dotenv
from test import crawl




def generate_ai_summary(target_url):
    load_dotenv()
    
    
    
    api_key = os.getenv("GOOGLE_API_KEY")
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.5-flash")


    # prompt = input("Enter prompt: ")
    # response = model.generate_content(prompt)
    # print(response.text)
    
    result = crawl()
        
        
    if not result :
        return "No significant vulnerabilities were detected during this scan."

    prompt = f"""
    You are a Senior Cyber Security Analyst. Review these vulnerability findings for {target_url}:
        
    {json.dumps( result, indent=2)}
        
    Provide a professional security report including:
    1. Executive Summary
    2. Detailed Analysis of each finding
    3. Actionable Remediation Steps (referencing OWASP Top 10 where applicable)
    4. Risk Assessment Score (0-100)
        
    Format the output in clear Markdown.
    """
        
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error generating AI report: {str(e)}"
    