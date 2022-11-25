import pathlib

import click

from .extractor import Extractor, Flipper


@click.group()
def cli():
    pass


@cli.command()
@click.argument('files', nargs=-1, required=True, type=click.File('rb'))
@click.option('--output-dir', type=click.Path(path_type=pathlib.Path, file_okay=False), default='to_flipper')
def to_flipper(files, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)

    for f in files:
        e = Extractor(f)
        out_file = output_dir / pathlib.Path(f.name).with_suffix('.nfc').name

        with open(out_file, 'w') as fh:
            fh.write(e.flipper_blocks() + '\n')


@cli.command()
@click.argument('files', nargs=-1, required=True, type=click.File('r'))
@click.option('--output-dir', type=click.Path(path_type=pathlib.Path, file_okay=False), default='from_flipper')
def from_flipper(files, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)

    for f in files:
        flipper = Flipper(f)
        out_file = output_dir / pathlib.Path(f.name).with_suffix('.mfd').name

        mfd_data, missing_block = flipper.mfd_data()
        if missing_block:
            click.secho('Warning: missing data will be replaced by zeroes', fg='red', bold=True, err=True)

        with open(out_file, 'wb') as fh:
            for block_id, block in sorted(mfd_data.items()):
                fh.write(block)


@cli.command('keys')
@click.argument('files', nargs=-1, required=True, type=click.File('rb'))
@click.option('--output', type=click.File('w'), default='-')
def extract_keys(files, output):
    all_keys = set()

    for f in files:
        e = Extractor(f)
        all_keys.update(e.extract_keys())

    for key in sorted(all_keys):
        output.write(key.upper() + '\n')


if __name__ == '__main__':
    cli()

