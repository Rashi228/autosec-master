"""
vector_db.py — Semantic Experience Memory
=========================================
Uses ChromaDB to store and retrieve past incident records
based on semantic similarity of the system state and logs.
"""

import chromadb
from chromadb.utils import embedding_functions
from typing import List, Dict, Optional
import os
import uuid

class VectorMemory:
    def __init__(self, db_path: str = "./chroma_db"):
        self.db_path = db_path
        # Ensures ChromaDB persists to disk
        self.client = chromadb.PersistentClient(path=self.db_path)
        
        # Use sentence-transformers for local fast embeddings
        self.ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        
        # Collection for storing agent experiences
        self.collection = self.client.get_or_create_collection(
            name="soc_experience_memory",
            embedding_function=self.ef
        )

    def store_experience(self, state_summary: str, action: dict, reward: float, success: bool):
        """
        Stores an experience in the vector database.
        state_summary should be a string representation of the environment.
        """
        doc_id = str(uuid.uuid4())
        
        # We embed the state_summary
        document = f"State: {state_summary} | Action: {action.get('action_type', '')} on {action.get('target', '')}"
        
        metadata = {
            "reward": reward,
            "success": success,
            "action_type": action.get("action_type", ""),
            "target": action.get("target", ""),
            "strategy": action.get("strategy", ""),
            "tactic": action.get("tactic", ""),
            "reasoning": action.get("reasoning", "")
        }
        
        self.collection.add(
            documents=[document],
            metadatas=[metadata],
            ids=[doc_id]
        )

    def retrieve_similar_actions(self, current_state_summary: str, n_results: int = 3) -> List[Dict]:
        """
        Retrieves the top n most similar past experiences to the current state.
        This provides 'memory' to the agent.
        """
        if self.collection.count() == 0:
            return []
            
        results = self.collection.query(
            query_texts=[current_state_summary],
            n_results=min(n_results, self.collection.count())
        )
        
        experiences = []
        if results and results["metadatas"] and results["metadatas"][0]:
            for i in range(len(results["metadatas"][0])):
                experiences.append({
                    "document": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                    "distance": results["distances"][0][i] if "distances" in results else 0.0
                })
                
        return experiences
