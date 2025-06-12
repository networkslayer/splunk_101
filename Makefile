# Default target
.PHONY: all
all: prepare build up

# Step 1: Prepare the BOTS dataset
.PHONY: prepare
prepare:
	@if [ ! -f botsv1_data_set.tgz ]; then \
		echo "Downloading BOTS dataset from S3..."; \
		curl -L -o botsv1_data_set.tgz https://s3.amazonaws.com/botsdataset/botsv1/splunk-pre-indexed/botsv1_data_set.tgz; \
	else \
		echo "Found local botsv1_data_set.tgz — skipping download."; \
	fi
	@echo "Extracting BOTS dataset to splunk_apps/botsv1_data_set..."
	@mkdir -p splunk_apps/botsv1_data_set
	@tar -xzf botsv1_data_set.tgz --strip-components=1 -C splunk_apps/botsv1_data_set

# Step 2: Build the Docker image
.PHONY: build
build:
	@echo "Building Docker image..."
	@docker compose build

# Step 3: Run the container
.PHONY: up
up:
	@docker compose up -d

# Optional cleanup
.PHONY: clean
clean:
	@echo "Cleaning extracted datasets and stopping containers..."
	@rm -rf splunk_apps/botsv1_data_set
	@docker compose down --volumes

# Optional full rebuild
.PHONY: rebuild
rebuild: clean all
