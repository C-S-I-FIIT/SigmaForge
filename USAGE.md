 # Sigma Rule Manager - Usage Guide

This document provides detailed instructions for using the Sigma Rule Manager utility.

## Prerequisites

Before using this utility, make sure you have the following:

1. Python 3.7 or higher installed
2. Required packages installed: `pip install -r requirements.txt`
3. Access to an Elasticsearch/Kibana environment
4. Sigma rules to convert and deploy

## Basic Usage

### Converting Rules

To convert Sigma rules to Elasticsearch queries:

```bash
python sigma_manager.py convert
```

This will:
- Read all `.yml` and `.yaml` files from the input directory (recursively)
- Convert them to Elasticsearch queries
- Save the converted rules to the output directory as JSON files
- Uploads them to Kibana

### Listing Existing Rules

To list all rules currently in Kibana:

```bash
python sigma_manager.py list-rules --config config.yaml
```

## Configuration

The configuration file (`config.yaml`) controls the behavior of the utility:

```yaml
elasticsearch:
  host: "http://localhost:9200"
  username: "elastic"
  password: "changeme"
  # ...

kibana:
  host: "http://localhost:5601"
  username: "elastic"
  password: "changeme"
  # ...

# Other configuration sections
```

### Important Configuration Options

#### Pipeline Options

Controls which pipeline to use for processing rules:

```yaml
pipeline:
  name: "sysmon"  # Options: sysmon, windows, linux, etc.
```

#### Rule Management Options

Controls how rules are managed in Kibana:

```yaml
rule_management:
  auto_upload: true  # Automatically upload rules to Kibana
  skip_existing: false  # Skip rules that already exist in Kibana
  update_on_change: true  # Update existing rules if changes detected
```
