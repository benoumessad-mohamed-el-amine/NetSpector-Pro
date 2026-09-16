"""Scan History & Profiles Management System for NetSpector Pro."""

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


DEFAULT_HISTORY_DIR = "netspector_history"


class HistoryManager:
    """Manages local storage, retrieval, and deletion of forensic scan session profiles."""

    def __init__(self, history_dir: str = DEFAULT_HISTORY_DIR):
        self.history_dir = os.path.abspath(history_dir)
        os.makedirs(self.history_dir, exist_ok=True)

    def save_profile(self, filename: str, triage_data: Dict[str, Any]) -> Dict[str, Any]:
        """Saves a forensic scan triage result as a persistent JSON profile."""
        now_dt = datetime.now(timezone.utc)
        timestamp_str = now_dt.strftime("%Y%m%d-%H%M%S")
        rand_suffix = f"{int(time.time() * 1000) % 10000:04d}"
        profile_id = f"PROF-{timestamp_str}-{rand_suffix}"

        summary = triage_data.get("metadata", {}).get("summary", {})
        alerts = triage_data.get("alerts", [])
        correlation = triage_data.get("attack_chain_correlation", {})

        profile_metadata = {
            "profile_id": profile_id,
            "created_at": now_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "timestamp_unix": time.time(),
            "filename": os.path.basename(filename) if filename else "Live Interface / Upload",
            "total_packets": summary.get("total_packets", 0),
            "total_flows": summary.get("total_flows", 0),
            "total_alerts": len(alerts),
            "severity_counts": summary.get("severity_counts", {}),
            "entities_count": correlation.get("total_correlated_entities", 0),
        }

        full_profile = {
            "profile_metadata": profile_metadata,
            "triage_data": triage_data,
        }

        profile_filepath = os.path.join(self.history_dir, f"{profile_id}.json")
        try:
            with open(profile_filepath, "w", encoding="utf-8") as f:
                json.dump(full_profile, f, indent=2)
        except Exception as e:
            print(f"Error saving history profile '{profile_id}': {e}")

        return profile_metadata

    def list_profiles(self) -> List[Dict[str, Any]]:
        """Returns a list of all saved profile summaries sorted by timestamp descending."""
        profiles = []
        if not os.path.exists(self.history_dir):
            return profiles

        for entry in os.listdir(self.history_dir):
            if entry.startswith("PROF-") and entry.endswith(".json"):
                filepath = os.path.join(self.history_dir, entry)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        meta = data.get("profile_metadata", {})
                        if meta:
                            profiles.append(meta)
                except Exception:
                    continue

        # Sort profiles by timestamp_unix descending
        profiles.sort(key=lambda p: p.get("timestamp_unix", 0), reverse=True)
        return profiles

    def get_profile(self, profile_id: str) -> Optional[Dict[str, Any]]:
        """Loads and returns the complete triage report for a given profile_id."""
        filepath = os.path.join(self.history_dir, f"{profile_id}.json")
        if not os.path.isfile(filepath):
            return None

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("triage_data")
        except Exception as e:
            print(f"Error reading history profile '{profile_id}': {e}")
            return None

    def delete_profile(self, profile_id: str) -> bool:
        """Deletes a history profile file."""
        filepath = os.path.join(self.history_dir, f"{profile_id}.json")
        if os.path.isfile(filepath):
            try:
                os.remove(filepath)
                return True
            except Exception as e:
                print(f"Error deleting profile '{profile_id}': {e}")
                return False
        return False
