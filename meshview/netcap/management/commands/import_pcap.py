from django.core.management.base import BaseCommand, CommandError

from netcap.pcap.importer import import_pcap_file
from netcap.pcap.reader import PcapFormatError


class Command(BaseCommand):
    help = "Import a .pcap file into a new CaptureSession, decoding every packet."

    def add_arguments(self, parser):
        parser.add_argument("pcap_path", help="Path to a classic-format .pcap file")
        parser.add_argument(
            "--name", help="Name for the CaptureSession (defaults to the filename)"
        )

    def handle(self, *args, **options):
        try:
            session, stats = import_pcap_file(options["pcap_path"], session_name=options.get("name"))
        except FileNotFoundError as exc:
            raise CommandError(f"file not found: {exc}")
        except PcapFormatError as exc:
            raise CommandError(f"not a supported pcap file: {exc}")

        self.stdout.write(self.style.SUCCESS(f"Imported session '{session.name}' (id={session.id})"))
        self.stdout.write(f"  packets:      {stats.packet_count}")
        self.stdout.write(f"  bytes:        {stats.byte_count}")
        self.stdout.write(f"  parse errors: {stats.parse_error_count}")
