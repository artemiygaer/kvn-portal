"""Проверить публичный GitHub asset штатным HTTPS-транспортом без установки."""

import argparse
import hashlib
import re

from v5.core.packages.github import GitHubPackages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--asset-id', type=int, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    if not 0 < args.asset_id < 2**63 or re.fullmatch(r'[0-9a-f]{64}', args.sha256) is None:
        parser.error('Некорректный идентификатор или SHA-256')
    url = f'https://api.github.com/repos/artemiygaer/kvn-portal/releases/assets/{args.asset_id}'
    digest, size = hashlib.sha256(), 0
    with GitHubPackages()._open(url, binary=True) as response:
        while chunk := response.read(65536):
            size += len(chunk)
            if size > 256 * 1024 * 1024:
                raise RuntimeError('Превышен лимит размера')
            digest.update(chunk)
    if digest.hexdigest() != args.sha256:
        raise RuntimeError('SHA-256 загруженного архива не совпадает')
    print(f'Публичный GitHub asset проверен штатным транспортом: {size} байт, SHA-256 совпадает.')


if __name__ == '__main__':
    main()
