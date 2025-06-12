# Splunk 101 - Docker Environment with BOTS v1 Dataset

A containerized Splunk environment pre-configured with all necessary apps and data to run the **Boss of the SOC (BOTS) v1** dataset for security training and analysis.

## Overview

This project provides a complete Splunk environment in Docker that includes:
- Splunk Enterprise (latest version)
- All required Splunk apps for BOTS v1 dataset analysis
- BOTS v1 dataset (either from local file or downloaded)
- Pre-configured environment ready for security analysis exercises
- **Complete workshop guide** (`Security4Rookiesv3.pdf`) for guided learning

## Features

- **Flexible Data Source**: Automatically uses local BOTS dataset if available, otherwise downloads it
- **Complete App Bundle**: Includes all necessary Splunk apps and technology add-ons
- **Easy Setup**: Simple Make commands for building and running

## Prerequisites

- Docker and Docker Compose installed
- At least 8GB of RAM recommended
- Sufficient disk space (BOTS dataset is ~6GB)

## Quick Start

### Using Make

```bash
# Build and run everything (uses local BOTS data if available)
make

# Or run individual steps
make prepare  # Extract BOTS dataset
make build    # Build Docker image
make up       # Start containers
```

### Environment Variables

- `SPLUNK_PASSWORD`: Default password is `changeme`
- Port `8000` is exposed for Splunk Web interface

## Usage

1. **Access Splunk Web**: Navigate to `http://localhost:8000`
2. **Login Credentials**:
   - Username: `admin`
   - Password: `changeme`
3. **Start Analyzing**: The BOTS v1 dataset and all required apps will be available

## Guided Learning

This environment includes a complete workshop guide for learning security analysis with Splunk:

📚 **Workshop Guide**: `docs/Security4Rookiesv3.pdf`

The workshop guide provides:
- Step-by-step exercises using the BOTS v1 dataset
- Security analysis techniques and methodologies
- Hands-on scenarios for threat hunting and investigation
- Best practices for using Splunk in security operations

**Recommended Learning Path**:
1. Start the Splunk environment using the steps above
2. Open the workshop PDF guide (`docs/Security4Rookiesv3.pdf`)
3. Follow along with the exercises in your running Splunk instance
4. Practice the security analysis techniques on real data

### Important Note for Workshop Exercises

When following the workshop guide, you may encounter search queries that don't return expected results (like searching for `imreallynotbatman.com`). This happens because Splunk may not be searching the BOTS dataset by default.

**Solution**: If searches don't return expected results, add `index="botsv1"` to your search queries:

```spl
# Instead of just:
imreallynotbatman.com

# Use:
index="botsv1" imreallynotbatman.com
```

This ensures your searches target the correct BOTS v1 dataset index.

## Included Splunk Apps

This environment includes the following pre-configured apps:

- **utbox**: Universal Forwarder toolbox
- **splunk_app_stream**: Splunk Stream App
- **Splunk_TA_fortinet_fortigate**: Fortinet FortiGate Technology Add-on
- **Splunk_TA_nessus**: Nessus Technology Add-on  
- **Splunk_TA_windows**: Windows Technology Add-on
- **TA-microsoft-sysmon**: Microsoft Sysmon Technology Add-on
- **TA-Suricata**: Suricata Technology Add-on
- **botsv1_data_set**: BOTS v1 dataset and dashboards

## Make Commands

| Command | Description |
|---------|-------------|
| `make all` | Complete setup: prepare → build → up |
| `make prepare` | Extract BOTS dataset (if USE_LOCAL_BOTS=true) |
| `make build` | Build Docker image with current configuration |
| `make up` | Start containers in detached mode |
| `make clean` | Remove extracted data and stop containers |
| `make rebuild` | Clean and rebuild everything |

## Customization

### Changing Splunk Password

Edit the `SPLUNK_PASSWORD` in `docker-compose.yml`:

```yaml
environment:
  - SPLUNK_PASSWORD=yournewpassword
```

## Troubleshooting

### Container Won't Start
- Check Docker daemon is running
- Ensure port 8000 is not in use by another service
- Verify sufficient disk space and memory

### BOTS Dataset Issues
- For download issues, check internet connectivity
- Large dataset may take time to extract/download

### Performance Issues
- Increase Docker memory allocation (8GB+ recommended)
- Consider using SSD storage for better I/O performance

## Data Persistence

Data is stored within the container. To persist data across container recreations:

1. Add volume mounts to `docker-compose.yml`
2. Or use `docker commit` to save container state

## Security Notes

- This is a dev / test system only -- please do not try and use it for production pusposes

## License

This project packages Splunk Enterprise and various apps. Please ensure compliance with:
- Splunk Enterprise licensing terms
- Individual app licensing requirements
- BOTS dataset usage terms

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Support

For issues related to:
- **Docker setup**: Check container logs with `docker compose logs`
- **Splunk configuration**: Refer to Splunk documentation
- **BOTS dataset**: Check Boss of the SOC resources 