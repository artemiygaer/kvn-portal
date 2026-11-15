"""Проверяемый интерфейс переноса, независимый от транспорта портала."""

from v5.core.packages.manifest import PackageError, json_object

from .crypto import ArchiveError, decrypt_archive, encrypt_archive
from .legacy import FORMAT, legacy_document
from .portable import PortableArchive, from_legacy


class MigrationService:
    def __init__(self, repository, *, export_data):
        self.repository, self.export_data = repository, export_data

    def preview(self, encrypted: bytes, phrase: str, *, mode: str, owner: str):
        try:
            document = json_object(decrypt_archive(encrypted, phrase))
        except PackageError:
            raise ArchiveError("migration_schema_invalid") from None
        if document.get("format") != FORMAT or type(document.get("version")) is not int:
            raise ArchiveError("migration_version_unsupported")
        if document["version"] == 1:
            archive = from_legacy(legacy_document(document))
        elif document["version"] == 2:
            archive = PortableArchive.parse(document)
        else:
            raise ArchiveError("migration_version_unsupported")
        return self.repository.preview(archive, mode=mode, owner=owner)

    def commit(self, ticket: str, *, owner: str) -> str:
        return self.repository.commit(ticket, owner=owner)

    def rollback(self, ticket: str) -> int:
        return self.repository.rollback(ticket)

    def export(self, phrase: str) -> bytes:
        # Источник включает проверенные данные модулей, а не их рабочие файлы целиком.
        archive = self.export_data()
        return encrypt_archive(PortableArchive.parse(archive.document()).encode(), phrase)
