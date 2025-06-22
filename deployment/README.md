# Deployment Documentation

## Overview

This directory contains deployment configurations and scripts for various environments.

## Deployment Options

- [Docker Compose](docker-compose.yml) - Local and development deployment
- [Production Scripts](scripts/) - Production deployment automation
- [Environment Configs](environments/) - Environment-specific configurations

## Deployment Environments

| Environment | Description | Configuration |
|-------------|-------------|---------------|
| **Development** | Local development | Docker Compose |
| **Staging** | Pre-production testing | Docker Compose + Secrets |
| **Production** | Live environment | Container orchestration |

---