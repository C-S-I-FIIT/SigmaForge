

<p align="center">
  <img src="assets/logo_sigmaforge.png" alt="SigmaForge Logo" width="300"/>
</p>

SigmaForge is a utility for managing, converting, and deploying Sigma rules to Kibana. It streamlines the process of transforming Sigma detection rules into Elasticsearch queries and managing them in your Kibana environment.

## Features

- Convert Sigma rules to Elasticsearch queries
- Automatic rule deployment to Kibana
- Support for multiple processing pipelines (Sysmon, Windows, etc.)
- Rule version management and updates
- Handling of outdated rules (disable or delete)
- Logging and error handling
- CLI interface

## Prerequisites

Before using this utility, make sure you have the following:

1. Python 3.7 or higher installed
2. Required packages installed: `pip install -r requirements.txt`
3. Access to an Elasticsearch/Kibana environment
4. Sigma rules to convert and deploy

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sigmaforge.git
cd sigmaforge
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure your environment by copying and modifying `config.yaml`

## Basic Usage

### Converting Rules

To convert Sigma rules to Elasticsearch queries and upload them to Kibana:

```bash
python sigma_manager.py convert
```

This will:
- Read all `.yml` and `.yaml` files from the input directory (recursively)
- Convert them to Elasticsearch queries
- Save the converted rules to the output directory as JSON files
- Upload them to Kibana (if enabled)

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

Controls which pipeline to use for processing rules:

```yaml
pipeline:
  name: "sysmon"  # Options: sysmon, windows, linux, etc.
```

Controls how rules are managed in Kibana:

```yaml
rule_management:
  auto_upload: true  # Automatically upload rules to Kibana
  skip_existing: false  # Skip rules that already exist in Kibana
  update_on_change: true  # Update existing rules if changes detected
```

## Pipeline Processing

SigmaForge supports multiple processing pipelines and allows for custom pipeline configurations. You can:
- Use built-in pipelines (Sysmon, Windows, etc.)
- Chain multiple pipelines together
- Define custom pipelines via `yaml` (see Sigma Rule documentation)
- Add custom post-processing steps