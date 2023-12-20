#!/usr/bin/env bash

# Deployment script

# Colors
C_RESET='\033[0m'
C_RED='\033[1;31m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'

# Logs
PREFIX_INFO="${C_GREEN}[INFO]${C_RESET} [$(date +%d-%m\ %T)]"
PREFIX_WARN="${C_YELLOW}[WARN]${C_RESET} [$(date +%d-%m\ %T)]"
PREFIX_CRIT="${C_RED}[CRIT]${C_RESET} [$(date +%d-%m\ %T)]"

# Main
AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-west-1}"
APP_DIR="${APP_DIR:-/home/ubuntu/ethereal-nfts/relayers}"
SECRETS_DIR="${SECRETS_DIR:-/home/ubuntu/relayers-secrets}"
STORAGE_PATH="${STORAGE_PATH:-/mnt/disks/storage}"
PARAMETERS_ENV_PATH="${SECRETS_DIR}/app.env"
SCRIPT_DIR="$(realpath $(dirname $0))"
USER_SYSTEMD_DIR="${USER_SYSTEMD_DIR:-/home/ubuntu/.config/systemd/user}"

SOURCE_INPUT="$1"
if [ -z "$SOURCE_INPUT" ]; then
  echo -e "${PREFIX_CRIT} Please specify SOURCE as first argument to script"
  exit 1
fi
TARGET_INPUT="$2"
if [ -z "$TARGET_INPUT" ]; then
  echo -e "${PREFIX_CRIT} Please specify TARGET as second argument to script"
  exit 1
fi

# Service file
RELAYERS_SERVICE_FILE="relayers.service"

set -eu

echo
echo
echo -e "${PREFIX_INFO} Install checkenv"
HOME=/home/ubuntu /usr/local/go/bin/go install github.com/bugout-dev/checkenv@latest

echo
echo
echo -e "${PREFIX_INFO} Retrieving deployment parameters"
if [ ! -d "${SECRETS_DIR}" ]; then
  mkdir "${SECRETS_DIR}"
  echo -e "${PREFIX_WARN} Created new secrets directory"
fi
AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION}" /home/ubuntu/go/bin/checkenv show aws_ssm+relayers:true >> "${PARAMETERS_ENV_PATH}"
chmod 0640 "${PARAMETERS_ENV_PATH}"

echo
echo
echo -e "${PREFIX_INFO} Retrieving RELAYERS_SOURCE_ERC721_WEB3_PROVIDER_URI parameter"
RELAYERS_SOURCE_ERC721_WEB3_PROVIDER_URI="$(AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION} /root/go/bin/checkenv show -raw -value aws_ssm+env_name:RELAYERS_SOURCE_ERC721_${SOURCE_INPUT}_WEB3_PROVIDER_URI)"
if [ -z "$RELAYERS_SOURCE_ERC721_WEB3_PROVIDER_URI" ]; then
  echo -e "${PREFIX_CRIT} Unable to fetch RELAYERS_SOURCE_ERC721_${SOURCE_INPUT}_WEB3_PROVIDER_URI parameter"
  exit 1
fi
echo "export RELAYERS_SOURCE_ERC721_WEB3_PROVIDER_URI=${RELAYERS_SOURCE_ERC721_WEB3_PROVIDER_URI}" >> "${PARAMETERS_ENV_PATH}"

echo
echo
echo -e "${PREFIX_INFO} Retrieving RELAYERS_TARGET_ETHEREAL_ADDRESS parameter"
RELAYERS_TARGET_ETHEREAL_ADDRESS="$(AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION} /root/go/bin/checkenv show -raw -value aws_ssm+env_name:RELAYERS_TARGET_ETHEREAL_${TARGET_INPUT}_ADDRESS)"
if [ -z "$RELAYERS_TARGET_ETHEREAL_ADDRESS" ]; then
  echo -e "${PREFIX_CRIT} Unable to fetch RELAYERS_TARGET_ETHEREAL_${TARGET_INPUT}_ADDRESS parameter"
  exit 1
fi
echo "export RELAYERS_TARGET_ETHEREAL_ADDRESS=${RELAYERS_TARGET_ETHEREAL_ADDRESS}" >> "${PARAMETERS_ENV_PATH}"

echo
echo
echo -e "${PREFIX_INFO} Retrieving RELAYERS_TARGET_ETHEREAL_CHAIN_ID parameter"
RELAYERS_TARGET_ETHEREAL_CHAIN_ID="$(AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION} /root/go/bin/checkenv show -raw -value aws_ssm+env_name:RELAYERS_TARGET_ETHEREAL_${TARGET_INPUT}_CHAIN_ID)"
if [ -z "$RELAYERS_TARGET_ETHEREAL_CHAIN_ID" ]; then
  echo -e "${PREFIX_CRIT} Unable to fetch RELAYERS_TARGET_ETHEREAL_${TARGET_INPUT}_CHAIN_ID parameter"
  exit 1
fi
echo "export RELAYERS_TARGET_ETHEREAL_CHAIN_ID=${RELAYERS_TARGET_ETHEREAL_CHAIN_ID}" >> "${PARAMETERS_ENV_PATH}"

echo
echo
echo -e "${PREFIX_INFO} Add instance local IP and AWS region to parameters"
echo "AWS_LOCAL_IPV4=$(ec2metadata --local-ipv4)" >> "${PARAMETERS_ENV_PATH}"
echo "AWS_REGION=${AWS_DEFAULT_REGION}" >> "${PARAMETERS_ENV_PATH}"

echo
echo
echo -e "${PREFIX_INFO} Prepare symlink to config"
if [ ! -f "${SECRETS_DIR}/config.json" ]; then
  ln -sf "${STORAGE_PATH}/config.json" "${SECRETS_DIR}/config.json"
  echo -e "${PREFIX_WARN} Created symling to config.json"
fi

echo
echo
echo -e "${PREFIX_INFO} Building executable relayers script with Go"
EXEC_DIR=$(pwd)
cd "${APP_DIR}"
HOME=/home/ubuntu /usr/local/go/bin/go build -o "${APP_DIR}/relayers" .
cd "${EXEC_DIR}"

echo
echo
echo -e "${PREFIX_INFO} Prepare user systemd directory"
if [ ! -d "${USER_SYSTEMD_DIR}" ]; then
  mkdir -p "${USER_SYSTEMD_DIR}"
  echo -e "${PREFIX_WARN} Created new user systemd directory"
fi

echo
echo
echo -e "${PREFIX_INFO} Replacing existing relayers service definition with ${RELAYERS_SERVICE_FILE}"
chmod 644 "${SCRIPT_DIR}/${RELAYERS_SERVICE_FILE}"
cp "${SCRIPT_DIR}/${RELAYERS_SERVICE_FILE}" "${USER_SYSTEMD_DIR}/${RELAYERS_SERVICE_FILE}"
XDG_RUNTIME_DIR="/run/user/$UID" systemctl --user daemon-reload
XDG_RUNTIME_DIR="/run/user/$UID" systemctl --user restart "${RELAYERS_SERVICE_FILE}"
