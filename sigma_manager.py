#!/usr/bin/env python3
"""
Sigma Rule Manager
A utility for converting Sigma rules to Elasticsearch queries and managing their deployment to Kibana.
"""

import os
import sys
import json
import yaml
import hashlib
import importlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union, cast

import click
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from tqdm import tqdm
from rich.style import Style
from loguru import logger


# Import sigma libraries - we'll handle import errors gracefully
try:
    from sigma.collection import SigmaCollection
    from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
    from sigma.pipelines.sysmon import sysmon_pipeline
    from sigma.rule import SigmaRule, SigmaLevel, SigmaRuleTag
    from sigma.processing.pipeline import ProcessingPipeline
    from sigma.processing.resolver import ProcessingPipelineResolver
    from sigma.plugins import InstalledSigmaPlugins
except ImportError:
    print("Error: Required sigma libraries not found. Please install dependencies:")
    print("pip install -r requirements.txt")
    sys.exit(1)

# Remove the existing logging setup and replace with loguru configuration
logger.remove()  # Remove default handler
logger.add(sys.stderr, level="INFO")
logger.add("sigma_manager.log", rotation="10 MB", retention="1 week")

console = Console()


class KibanaClient:
    """Client for interacting with Kibana API."""
    
    def __init__(self, kibana_config: Dict[str, Any]):
        """
        Initialize the Kibana client.
        
        Args:
            kibana_config: Kibana configuration dictionary.
        """
        self.kibana_url = kibana_config.get("host", "")
        self.space_id = kibana_config.get("space_id", "default")
        
        username = kibana_config.get("username")
        password = kibana_config.get("password")
        if username is not None and password is not None:
            self.auth = (str(username), str(password))
        else:
            self.auth = None
            
        self.ssl_verify = kibana_config.get("ssl_verify", True)
        self.timeout = kibana_config.get("timeout", 30)
        
        # Standard headers for Kibana API requests
        self.headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    
    def _build_url(self, path: str) -> str:
        """Build a full URL with space ID if needed."""
        if self.space_id != "default":
            return f"{self.kibana_url}/s/{self.space_id}/{path.lstrip('/')}"
        return f"{self.kibana_url}/{path.lstrip('/')}"
    
    def get_rule(self, rule_id: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Get a rule by ID from Kibana.
        
        Args:
            rule_id: The ID of the rule to get.
            
        Returns:
            Tuple of (success, response_data)
        """
        check_url = self._build_url(f"api/alerting/rule/{rule_id}")
        
        try:
            response = requests.get(
                check_url,
                auth=self.auth,
                headers=self.headers,
                verify=self.ssl_verify,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return True, response.json()
            elif response.status_code == 404:
                return False, {"error": "Rule not found"}
            else:
                logger.error(f"Unexpected response when checking rule {rule_id}: {response.text}")
                return False, {"error": f"Unexpected response: {response.status_code}"}
        except Exception as e:
            logger.error(f"Error communicating with Kibana: {e}")
            return False, {"error": str(e)}
    
    def create_rule(self, kibana_rule: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Create a new rule in Kibana.
        
        Args:
            kibana_rule: The rule data to create.
            
        Returns:
            Tuple of (success, message)
        """
        rule_id = kibana_rule.get("params", {}).get("ruleId", "")
        if not rule_id:
            return False, "Rule ID not found in rule data"
            
        create_url = self._build_url(f"api/alerting/rule/{rule_id}")
        
        try:
            create_response = requests.post(
                create_url,
                auth=self.auth,
                headers=self.headers,
                json=kibana_rule,
                verify=self.ssl_verify,
                timeout=self.timeout
            )
            
            if create_response.status_code in (200, 201):
                return True, f"Rule {rule_id} created successfully."
            else:
                logger.error(f"Failed to create rule {rule_id}: {create_response.text}")
                return False, f"Failed to create rule {rule_id}: {create_response.status_code}"
        except Exception as e:
            logger.error(f"Error creating rule in Kibana: {e}")
            return False, f"Error creating rule in Kibana: {e}"
    
    def update_rule(self, rule_id: str, kibana_rule: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Update an existing rule in Kibana.
        
        Args:
            rule_id: The ID of the rule to update.
            kibana_rule: The updated rule data.
            
        Returns:
            Tuple of (success, message)
        """
        update_url = self._build_url(f"api/alerting/rule/{rule_id}")
        
        # Include the rule_id in the update
        update_data = kibana_rule.copy()
        
        # Remove fields that can't be updated
        for field in ["consumer", "enabled", "rule_type_id"]:
            if field in update_data:
                del update_data[field]
        
        try:
            update_response = requests.put(
                update_url,
                auth=self.auth,
                headers=self.headers,
                json=update_data,
                verify=self.ssl_verify,
                timeout=self.timeout
            )
            
            if update_response.status_code in (200, 201):
                return True, f"Rule {rule_id} updated successfully."
            else:
                logger.error(f"Failed to update rule {rule_id}: {update_response.text}")
                return False, f"Failed to update rule {rule_id}: {update_response.status_code}"
        except Exception as e:
            logger.error(f"Error updating rule in Kibana: {e}")
            return False, f"Error updating rule in Kibana: {e}"
    
    def disable_rule(self, rule_id: str) -> Tuple[bool, str]:
        """
        Disable a rule in Kibana.
        
        Args:
            rule_id: The ID of the rule to disable.
            
        Returns:
            Tuple of (success, message)
        """
        disable_url = self._build_url(f"api/alerting/rule/{rule_id}/_disable")
        
        try:
            response = requests.post(
                disable_url,
                auth=self.auth,
                headers=self.headers,
                verify=self.ssl_verify,
                timeout=self.timeout
            )
            
            if response.status_code in (200, 201, 204):
                return True, f"Rule {rule_id} disabled successfully."
            else:
                logger.error(f"Failed to disable rule {rule_id}: {response.text}")
                return False, f"Failed to disable rule {rule_id}: {response.status_code}"
        except Exception as e:
            logger.error(f"Error disabling rule in Kibana: {e}")
            return False, f"Error disabling rule in Kibana: {e}"
    
    def enable_rule(self, rule_id: str) -> Tuple[bool, str]:
        """
        Enable a rule in Kibana.
        
        Args:
            rule_id: The ID of the rule to enable.
        """
        enable_url = self._build_url(f"api/alerting/rule/{rule_id}/_enable")
        
        try:
            response = requests.post(
                enable_url,
                auth=self.auth,
                headers=self.headers,
                verify=self.ssl_verify,
                timeout=self.timeout
            )
            
            if response.status_code in (200, 201, 204):
                return True, f"Rule {rule_id} enabled successfully."
            else:
                logger.error(f"Failed to enable rule {rule_id}: {response.text}")
                return False, f"Failed to enable rule {rule_id}: {response.status_code}"
        except Exception as e:
            logger.error(f"Error enabling rule in Kibana: {e}")
            return False, f"Error enabling rule in Kibana: {e}"
        
    
    def delete_rule(self, rule_id: str) -> Tuple[bool, str]:
        """
        Delete a rule from Kibana.
        
        Args:
            rule_id: The ID of the rule to delete.
            
        Returns:
            Tuple of (success, message)
        """
        delete_url = self._build_url(f"api/alerting/rule/{rule_id}")
        
        try:
            response = requests.delete(
                delete_url,
                auth=self.auth,
                headers=self.headers,
                verify=self.ssl_verify,
                timeout=self.timeout
            )
            
            if response.status_code in (200, 204):
                return True, f"Rule {rule_id} deleted successfully."
            else:
                logger.error(f"Failed to delete rule {rule_id}: {response.text}")
                return False, f"Failed to delete rule {rule_id}: {response.status_code}"
        except Exception as e:
            logger.error(f"Error deleting rule from Kibana: {e}")
            return False, f"Error deleting rule from Kibana: {e}"
    
    def get_all_rules(self) -> List[Dict[str, Any]]:
        """
        Get a list of all rules from Kibana.
        
        Returns:
            List of rules from Kibana.
        """
        find_url = self._build_url("api/detection_engine/rules/_find")
        
        try:
            response = requests.get(
                find_url,
                auth=self.auth,
                headers=self.headers,
                params={"per_page": 1000},  # Get up to 1000 rules
                verify=self.ssl_verify,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json().get("data", [])
            else:
                logger.error(f"Failed to fetch rules from Kibana: {response.text}")
                return []
        except Exception as e:
            logger.error(f"Error communicating with Kibana: {e}")
            return []
    
    def upload_rule(self, kibana_rule: Dict[str, Any], update_on_change: bool = True) -> Tuple[bool, bool, str]:
        """
        Upload a rule to Kibana, creating or updating as needed.
        
        Args:
            kibana_rule: The rule formatted for Kibana.
            update_on_change: Whether to update the rule if it already exists.
            
        Returns:
            Tuple of (success, was_updated, message)
        """
        rule_id = kibana_rule.get("params", {}).get("ruleId", "")
        if not rule_id:
            return False, "Rule ID not found in rule data"
        
        # Check if rule already exists
        success, existing_rule = self.get_rule(rule_id)
        
        if success:
            # Rule exists, check if it needs updating
            # Remove keys from existing_rule that are not in kibana_rule
            keys_to_remove = [key for key in existing_rule if key not in kibana_rule]
            for key in keys_to_remove:
                existing_rule.pop(key, None)
            
            # Calculate hashes for comparison
            existing_hash = hashlib.md5(json.dumps(existing_rule, sort_keys=True).encode()).hexdigest()
            new_hash = hashlib.md5(json.dumps(kibana_rule, sort_keys=True).encode()).hexdigest()
            
            if existing_hash == new_hash:
                return True, False, f"Rule {rule_id} already exists and is up to date."
            
            if update_on_change:
                success, message = self.update_rule(rule_id, kibana_rule)
                return success, True, message
            else:
                return True, False, f"Rule {rule_id} exists but was not updated (update_on_change is disabled)."
        else:
            # Rule doesn't exist, create it
            success, message = self.create_rule(kibana_rule)
            return success, False, message


class SigmaRuleManager:
    """Manages the conversion and deployment of Sigma rules to Elasticsearch/Kibana."""

    def __init__(self, config_path: str):
        """
        Initialize the Sigma Rule Manager.
        
        Args:
            config_path: Path to the configuration YAML file.
        """
        self.config = self._load_config(config_path)
        self.kibana_config = self.config.get("kibana", {})
        self.sigma_config = self.config.get("sigma", {})
        self.backend_config = self.config.get("backend", {})
        self.pipeline_config = self.config.get("pipelines", [])
        self.rule_management = self.config.get("rule_management", {})
        
        self.plugins = InstalledSigmaPlugins.autodiscover()
        self.pipelines = self.plugins.pipelines
        
        # Initialize backend and pipeline
        self.pipeline = self._init_pipelines()
        self.backend = self._init_backend()
        
        # Initialize Kibana client
        self.kibana_client = KibanaClient(self.kibana_config)

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load configuration from {config_path}: {e}")
            raise

    def _init_backend(self) -> Any:
        """Initialize the appropriate backend based on configuration."""
        backend_type = self.backend_config.get("type", "lucene")
        backend_kwargs = self.backend_config.get("options", {})
        return LuceneBackend(processing_pipeline=self.pipeline, **backend_kwargs)

    def _init_pipelines(self) -> Any:
        """Initialize the appropriate pipeline like Sysmon based on configuration."""

        pipeline_list = [p for p in self.pipeline_config if not p.endswith(".yml") and not p.endswith(".yaml")]
        extra_pipelines = [p for p in self.pipeline_config if p.endswith(".yml") or p.endswith(".yaml")]
        
        pipeline_resolver = self.plugins.get_pipeline_resolver()
        backend_type = self.backend_config.get("type", "lucene")
        
        plugin_pipelines = list(pipeline_resolver.list_pipelines())
        _plugin_pipelines_names = [name for name, pipeline in plugin_pipelines]
        
        unsupported_pipelines = []
        
        for name, pipeline in plugin_pipelines:
            if "all" in pipeline.allowed_backends:
                continue
            if name == "sysmon":
                continue    
            if backend_type not in pipeline.allowed_backends:
                unsupported_pipelines.append(name)
        
        for name in pipeline_list:
            if name not in _plugin_pipelines_names:
                unsupported_pipelines.append(name)
            
        
        if unsupported_pipelines:
            logger.warning(f"Unsupported pipelines: {unsupported_pipelines}")
            
            
        pipeline_list = [p for p in pipeline_list if p not in unsupported_pipelines]
        main_pipeline = pipeline_resolver.resolve(pipeline_list)

        extra_pipelines_processed = []
        for pipeline in extra_pipelines:
            try:
                with open(pipeline, 'r') as f:
                    _data = f.read()
                    extra_pipelines_processed.append(ProcessingPipeline.from_yaml(_data))
                    logger.success(f"Loaded postprocessing pipeline {pipeline}")
            except Exception as e:
                logger.error(f"Failed to load postprocessing pipeline {pipeline}: {e}")
                raise
            
        for pipeline in extra_pipelines_processed:
            main_pipeline += pipeline
        
        return main_pipeline

    def process_rule_file(self, rule_path: Path) -> Tuple[Union[Dict[str, Any], None], bool]:
        """
        Process a single Sigma rule file, converting it to an Elasticsearch query.
        
        Args:
            rule_path: Path to the Sigma rule file.
            
        Returns:
            Tuple containing the converted rule details and a boolean indicating if the rule is enabled.
        """
        try:
            # Parse Sigma rule
            with open(rule_path, 'r', encoding='utf-8') as file:
                rule_content = file.read()
                
            try:
                # Parse the rule with SigmaCollection
                sigma_collection = SigmaCollection.from_yaml(rule_content)
            except yaml.YAMLError as ye:
                logger.warning(f"Skipping {rule_path}: Invalid YAML format - {str(ye)}")
                return None, False
            except Exception as e:
                logger.warning(f"Skipping {rule_path}: Invalid Sigma rule format - {str(e)}")
                return None, False
            
            converted_query = self.backend.convert(sigma_collection)
            kibana_request = self.backend.finalize_query_siem_rule(rule=sigma_collection.rules[0], query=converted_query[0], index=0, state=None)
            logger.debug(kibana_request)
            
            if kibana_request.get("params", {}).get("severity", "") == "informational":
                logger.warning(f"Severity is informational, which is not supported by Kibana, setting to low for {kibana_request['params']['ruleId']}")
                kibana_request["params"]["severity"] = "low"
            
            rules_content = yaml.safe_load(rule_content)
            if rules_content.get("enabled", True) == False:
                logger.warning(f"Rule {rule_path} marked as disabled, will disable in Kibana")
                return kibana_request, False
            
            return kibana_request, True
            
        except Exception as e:
            logger.error(f"Error processing rule {rule_path}: {e}")
            return None, False
    
    def disable_rule_in_kibana(self, rule_id: str) -> bool:
        """
        Disable a rule in Kibana.
        
        Args:
            rule_id: The ID of the rule to disable.
            
        Returns:
            True if successful, False otherwise
        """
        success, message = self.kibana_client.disable_rule(rule_id)
        if success:
            logger.debug(message)
        else:
            logger.error(message)
        return success
    
    def enable_rule_in_kibana(self, rule_id: str) -> bool:
        """
        Enable a rule in Kibana.
        
        Args:
            rule_id: The ID of the rule to enable.
            
        Returns:
            True if successful, False otherwise
        """
        success, message = self.kibana_client.enable_rule(rule_id)
        if success:
            logger.debug(message)
        else:
            logger.error(message)
        return success
    
    def upload_rule_to_kibana(self, kibana_rule: Dict[str, Any]) -> Tuple[bool, bool, str]:
        """
        Upload a rule to Kibana.
        
        Args:
            kibana_rule: The rule formatted for Kibana.
            
        Returns:
            Tuple of (success, message)
        """
        update_on_change = self.rule_management.get("update_on_change", True)
        return self.kibana_client.upload_rule(kibana_rule, update_on_change)
    
    def get_kibana_rules(self) -> List[Dict[str, Any]]:
        """
        Get a list of all rules from Kibana.
        
        Returns:
            List of rules from Kibana.
        """
        return self.kibana_client.get_all_rules()

    def manage_outdated_rules(self, processed_rule_ids: List[str]) -> Dict[str, int]:
        """
        Manage outdated Sigma rules in Kibana.
        
        This function will either disable or delete rules whose names start with "SIGMA"
        that weren't updated or created in the current processing run.
        
        Args:
            processed_rule_ids: List of rule IDs that were processed in the current run.
            
        Returns:
            Statistics about the operation.
        """
        stats = {
            "disabled": 0,
            "deleted": 0,
            "errors": 0
        }
        
        # Get current rules from Kibana
        existing_rules = self.get_kibana_rules()
        
        # Get configuration for handling outdated rules
        outdated_action = self.rule_management.get("outdated_action", "disable")
        if outdated_action not in ["disable", "delete"]:
            logger.warning(f"Invalid outdated_action '{outdated_action}', defaulting to 'disable'")
            outdated_action = "disable"
        
        for rule in existing_rules:
            rule_id = rule.get("rule_id")
            rule_name = rule.get("name", "")
            
            # Check if the rule is a Sigma rule that wasn't processed
            if rule_name.startswith("SIGMA") and rule_id and rule_id not in processed_rule_ids:
                try:
                    if outdated_action == "disable":
                        # Disable the rule
                        success, message = self.kibana_client.disable_rule(str(rule_id))
                        if success:
                            stats["disabled"] += 1
                            logger.info(f"Disabled outdated rule: {rule_name} (ID: {rule_id})")
                        else:
                            stats["errors"] += 1
                            logger.error(f"Failed to disable rule {rule_name}: {message}")
                            
                    elif outdated_action == "delete":
                        # Delete the rule
                        success, message = self.kibana_client.delete_rule(str(rule_id))
                        if success:
                            stats["deleted"] += 1
                            logger.info(f"Deleted outdated rule: {rule_name} (ID: {rule_id})")
                        else:
                            stats["errors"] += 1
                            logger.error(f"Failed to delete rule {rule_name}: {message}")
                            
                except Exception as e:
                    stats["errors"] += 1
                    logger.error(f"Error managing outdated rule {rule_name}: {e}")
        
        logger.info(f"Outdated rules management complete: {stats['disabled']} disabled, {stats['deleted']} deleted, {stats['errors']} errors")
        return stats

    def process_rules(self, 
                     input_dir: str, 
                     output_dir: Optional[str] = None, 
                     upload: bool = True) -> Dict[str, int]:
        """
        Process all Sigma rules in the input directory.
        
        Args:
            input_dir: Directory containing Sigma rule files.
            output_dir: Optional directory to save converted rules.
            upload: Whether to upload rules to Kibana.
            
        Returns:
            Statistics about the processing.
        """
        input_path = Path(input_dir)
        
        if not input_path.exists():
            logger.error(f"Input directory {input_dir} does not exist")
            raise FileNotFoundError(f"Input directory {input_dir} does not exist")
        
        # Prepare output directory if specified
        if output_dir:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
        
        # Find all YAML files
        rule_files = list(input_path.glob("**/*.yml")) + list(input_path.glob("**/*.yaml"))
        
        # Statistics
        stats = {
            "total": len(rule_files),
            "processed": 0,
            "conversion_errors": 0,
            "upload_success": 0,
            "upload_errors": 0,
            "disabled": 0,
            "enabled": 0,
            "updated": 0,
            "skipped": 0
        }
        
        # Track processed rule IDs for managing outdated rules
        processed_rule_ids = []
            
        for rule_file in rule_files:
            try:
                # Process the rule 
                converted_rule_kibana_req, enabled = self.process_rule_file(rule_file)
                if converted_rule_kibana_req is None:
                    stats["skipped"] += 1
                    continue
                
                # Store the rule ID for tracking regardless of enabled status
                rule_id = converted_rule_kibana_req.get("params", {}).get("ruleId")
                if rule_id:
                    processed_rule_ids.append(rule_id)
                
                stats["processed"] += 1
                
                # Save to output directory if specified
                if output_dir:
                    output_file = f"{output_dir}/{rule_file.stem}.json"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(converted_rule_kibana_req, f, indent=2)
                
                # Upload to Kibana if requested
                if upload and self.rule_management.get("auto_upload", True):
                    success, was_updated, message = self.upload_rule_to_kibana(converted_rule_kibana_req)
                    
                    if success:
                        stats["upload_success"] += 1
                        logger.info(message)
                        if was_updated:
                            stats["updated"] += 1
                    else:
                        stats["upload_errors"] += 1
                        logger.error(message)
                    
                    if enabled:
                        self.enable_rule_in_kibana(rule_id)
                        stats["enabled"] += 1
                    else:
                        self.disable_rule_in_kibana(rule_id)
                        stats["disabled"] += 1
                        logger.warning(f"Rule {rule_file.stem} in Kibana disabled")
                
            except Exception as e:
                stats["conversion_errors"] += 1
                logger.error(f"Error processing rule {rule_file}: {e}")
        
        # Handle outdated rules if enabled
        if upload and self.rule_management.get("manage_outdated", True):
            outdated_stats = self.manage_outdated_rules(processed_rule_ids)
            
            # Add outdated stats to overall stats
            stats.update({
                "outdated_disabled": outdated_stats["disabled"],
                "outdated_deleted": outdated_stats["deleted"],
                "outdated_errors": outdated_stats["errors"]
            })
        
        # Log final statistics
        logger.info(f"Processing complete: {stats['processed']} processed, {stats['skipped']} skipped, {stats['conversion_errors']} errors")
        return stats


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Sigma Rule Manager - Convert and manage Sigma rules for Elasticsearch and Kibana."""
    pass


@cli.command("convert")
@click.option("--input", "-i", required=True, help="Input directory containing Sigma rules.", default="rules")
@click.option("--output", "-o", help="Output directory for converted rules.", default="converted_rules")
@click.option("--config", "-c", default="config.yaml", help="Path to configuration file.")
@click.option("--no-upload", is_flag=True, help="Don't upload rules to Kibana.")
def convert_rules(input: str, output: Optional[str], config: str, no_upload: bool):
    """Convert Sigma rules to Elasticsearch queries and optionally upload to Kibana."""
    try:
        manager = SigmaRuleManager(config)
        
        stats = manager.process_rules(manager.sigma_config['input_dir'], manager.sigma_config['output_dir'], not no_upload)
        
        # Display results
        table = Table(title="Rule Processing Results")
        table.add_column("Metric", style="green")
        table.add_column("Count", style="cyan", justify="right")
        
        table.add_row("Total rules found", str(stats["total"]))
        table.add_row("Successfully processed", str(stats["processed"]))
        table.add_row("Conversion errors", str(stats["conversion_errors"]))
        
        if not no_upload:
            table.add_row("Successfully uploaded", str(stats["upload_success"]))
            table.add_row("Upload errors", str(stats["upload_errors"]))
            table.add_row("Rules enabled", str(stats["enabled"]))
            table.add_row("Rules disabled", str(stats["outdated_disabled"]))
            table.add_row("Rules updated", str(stats["updated"]))
            table.add_row("Rules deleted", str(stats["outdated_deleted"]))
            # Add outdated rule stats if available
            # if "outdated_disabled" in stats:
            #     table.add_row("Outdated rules disabled", str(stats["outdated_disabled"]))
            # if "outdated_deleted" in stats:
            #     table.add_row("Outdated rules deleted", str(stats["outdated_deleted"]))
            #if "outdated_errors" in stats:
            #    table.add_row("Rule errors", str(stats["outdated_errors"]))
        
        console.print(table)
        
    except Exception as e:
        logger.error(f"Error during rule conversion: {e}")
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


@cli.command("list-rules")
@click.option("--config", "-c", default="config.yaml", help="Path to configuration file.")
def list_rules(config: str):
    """List all rules in Kibana."""
    try:
        manager = SigmaRuleManager(config)
        rules = manager.get_kibana_rules()
        
        if not rules:
            console.print("[yellow]No rules found in Kibana.[/yellow]")
            return
        
        table = Table(title=f"Kibana Rules ({len(rules)} rules)")
        table.add_column("Name", style="white")
        table.add_column("ID", style="cyan")
        table.add_column("Type", style="blue")
        table.add_column("Severity")
        table.add_column("Enabled", style="yellow")
        
        for rule in rules:
            severity = rule.get("severity", "N/A")
            table.add_row(
                rule.get("name", "N/A"),
                rule.get("rule_id", "N/A"),
                rule.get("type", "N/A"),
                f"[{get_severity_color(severity)}]{severity}[/]",
                "Yes" if rule.get("enabled", False) else "No"
            )
        
        console.print(table)
        
    except Exception as e:
        logger.error(f"Error listing rules: {e}")
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


def get_severity_color(severity: str) -> str:
    severity_colors = {
        "low": "green",
        "medium": "yellow",
        "high": "red"
    }
    return severity_colors.get(severity.lower(), "white")  # default to white if severity not found


if __name__ == "__main__":
    cli()