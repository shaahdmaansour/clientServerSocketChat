from supabase import create_client
import os
from datetime import datetime

class DatabaseManager:
    def __init__(self):
        # Replace these with your Supabase credentials
        SUPABASE_URL = "https://wgirubfxikwgvvsvmfpy.supabase.co"
        SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndnaXJ1YmZ4aWt3Z3Z2c3ZtZnB5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzU0ODkzNzgsImV4cCI6MjA1MTA2NTM3OH0.wYQTZaksmZnot_EHYGqsc9kmtgGTeTKopvqtCp_0fn8"
        
        self.supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

    def save_message(self, sender, message, is_private=False, recipient=None):
        try:
            data = {
                "sender": sender,
                "message": message,
                "is_private": is_private,
                "recipient": recipient,
                "timestamp": datetime.now().isoformat()
            }
            self.supabase.table('messages').insert(data).execute()
        except Exception as e:
            print(f"Error saving message: {e}")

    def get_chat_history(self, user, limit=50):
        try:
            # Get public messages and private messages where user is sender or recipient
            response = self.supabase.table('messages').select('*').or_(
                f"is_private.eq.false,recipient.eq.{user},sender.eq.{user}"
            ).order('timestamp', desc=True).limit(limit).execute()
            
            return response.data
        except Exception as e:
            print(f"Error fetching chat history: {e}")
            return [] 

###
    def clear_chat_history(self):
        try:
            self.cursor.execute("DELETE FROM messages")
            self.conn.commit()
        except Exception as e:
            print(f"Error clearing chat history: {e}") 
###