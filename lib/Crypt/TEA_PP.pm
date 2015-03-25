package Crypt::TEA_PP;

# ABSTRACT: Pure Perl Implementation of the Tiny Encryption Algorithm

use strict;
use warnings;
use utf8;
use integer;

use Carp;
use List::MoreUtils qw(all part);

use vars qw ($VERSION);

$VERSION = '0.02';

=head1 SYNOPSIS

   use Crypt::TEA_PP;
   use Crypt::CBC;

   my $tea = Crypt::TEA_PP->new( $key );
   my $cbc = Crypt::CBC->new( -cipher => $tea );

   my $text = 'The quick brown fox jumps over the lazy dog';
   my $cipher_text = $cbc->encrypt( $text );

   my $plain_text = $cbc->decrypt( $cipher_text );

=head1 DESCRIPTION

TEA is a 64-bit symmetric block cipher with a 128-bit key and a variable number of rounds (32 is recommended).
It has a low setup time, and depends on a large number of rounds for security, rather than a complex algorithm.
It was developed by David J. Wheeler and Roger M. Needham,
and is described at L<http://www.ftp.cl.cam.ac.uk/ftp/papers/djw-rmn/djw-rmn-tea.html>

This module implements TEA encryption. It supports the Crypt::CBC interface, with the following functions.

=cut

my $DELTA = 0x9e3779b9;
my $SUMATION = 0xc6ef3720;
my $ROUNDS = 32;
my $KEY_SIZE = 16;
my $ELEMENTS_IN_KEY = $KEY_SIZE / 4;
my $BLOCK_SIZE = 8;
my $ELEMENTS_IN_BLOCK = $BLOCK_SIZE / 4;

=method keysize

Returns the maximum TEA key size, 16 bytes.

=cut

use constant keysize => $KEY_SIZE;

=method blocksize

Returns the TEA block size, which is 8 bytes. This function exists so that Crypt::TEA_PP can work with Crypt::CBC.

=cut

use constant blocksize => $BLOCK_SIZE;

=method new

    my $tea =  Crypt::TEA_PP->new( $key, $rounds );

This creates a new Crypt::TEA_PP object with the specified key.
The optional rounds parameter specifies the number of rounds of encryption to perform, and defaults to 32.

=cut

sub new {
    my $class = shift;
    my $key = shift;
    my $rounds = shift // $ROUNDS;
    my $tea_key;
    croak( 'key is required' ) if not defined $key;
    if ( my $ref_of_key = ref( $key ) ) {
        croak( sprintf( 'key must be a %d-byte-long STRING or a reference of ARRAY', $KEY_SIZE ) ) if not $ref_of_key eq 'ARRAY';
        croak( sprintf( 'key must has %d elements if key is a reference of ARRAY', $ELEMENTS_IN_KEY ) ) if scalar( @{ $key } ) != $ELEMENTS_IN_KEY;
        croak( 'each element of key must be a NUMBER if key is a reference of ARRAY' ) if not all { /^-?\d+$/ } @{ $key };
        $tea_key = $key;
    } else {
        croak( sprintf( 'key must be a %d-byte-long STRING or a reference of ARRAY', $KEY_SIZE ) ) if length $key != $KEY_SIZE;
        $tea_key = key_setup($key);
    }
    croak( 'rounds must be a positive NUMBER' ) if $rounds !~ /^\d+$/;
    my $self = {
        key => $tea_key,
        rounds => $rounds,
    };
    bless $self, ref($class) || $class;
}

=method encrypt

    $cipher_text = $tea->encrypt($plain_text);

Encrypts blocksize() bytes of $plain_text and returns the corresponding ciphertext.

=cut

sub encrypt {
    my $self = shift;
    my $plain_text = shift;
    croak( sprintf( 'block size must be %d', $BLOCK_SIZE) ) if length($plain_text) != $BLOCK_SIZE;
    my @block = unpack 'N*', $plain_text;
    my $cipher_text_ref = $self->encrypt_block( \@block );
    return pack( 'N*', @{$cipher_text_ref} );
}

=method decrypt

    $plain_text = $tea->decrypt($cipher_text);

Decrypts blocksize() bytes of $cipher_text and returns the corresponding plaintext.

=cut

sub decrypt {
    my $self = shift;
    my $cipher_text = shift;
    croak( sprintf( 'block size must be %d', $BLOCK_SIZE) ) if length($cipher_text) != $BLOCK_SIZE;
    my @block = unpack 'N*', $cipher_text;
    my $plain_text_ref = $self->decrypt_block( \@block );
    return pack( 'N*', @{$plain_text_ref} );
}

sub encrypt_block {
    my $self = shift;
    my $block_ref = shift;
    my $key_ref = $self->{key};

    croak( sprintf( 'block must has %d elements', $ELEMENTS_IN_BLOCK ) ) if scalar( @{ $block_ref } ) != $ELEMENTS_IN_BLOCK;
    croak( sprintf( 'key must has %d elements', $ELEMENTS_IN_KEY ) ) if scalar( @{ $key_ref } ) != $ELEMENTS_IN_KEY;

    my @block = map { $_ & 0xffff_ffff } @{ $block_ref };
    my @key = map { $_ & 0xffff_ffff } @{ $key_ref };
    my $sumation = 0 & 0xffff_ffff;
    my $delta = $DELTA & 0xffff_ffff;
        printf("\t--> block[0] = %d, block[1] = %d\n", $block[0], $block[1]);
    for my $i ( 0 .. $self->{rounds}-1 ) {
        $sumation = ( $sumation + $delta ) & 0xffff_ffff;
        $block[0] = ( $block[0] + ( ( ( ( ( ( ( ( $block[1] << 4 ) & 0xffff_ffff ) + $key[0] ) & 0xffff_ffff ) ^ ( ( $block[1] + $sumation ) & 0xffff_ffff ) ) & 0xffff_ffff ) ^ ( ( ( ( $block[1] >> 5 ) & 0xffff_ffff ) +  $key[1] ) & 0xffff_ffff ) ) & 0xffff_ffff ) ) & 0xffff_ffff;
        $block[1] = ( $block[1] + ( ( ( ( ( ( ( ( $block[0] << 4 ) & 0xffff_ffff ) + $key[2] ) & 0xffff_ffff ) ^ ( ( $block[0] + $sumation ) & 0xffff_ffff ) ) & 0xffff_ffff ) ^ ( ( ( ( $block[0] >> 5 ) & 0xffff_ffff ) +  $key[3] ) & 0xffff_ffff ) ) & 0xffff_ffff ) ) & 0xffff_ffff;
        #printf("\t--> Encrypting block round %d of %d\n", $i + 1, $ROUNDS);
        #printf("\t--> block[0] = %d, block[1] = %d\n", $block[0], $block[1]);
    }
    return \@block;
}

sub decrypt_block {
    my $self = shift;
    my $block_ref = shift;
    my $key_ref = $self->{key};

    croak( sprintf( 'block must has %d elements', $ELEMENTS_IN_BLOCK ) ) if scalar( @{ $block_ref } ) != $ELEMENTS_IN_BLOCK;
    croak( sprintf( 'key must has %d elements', $ELEMENTS_IN_KEY ) ) if scalar( @{ $key_ref } ) != $ELEMENTS_IN_KEY;

    my @block = map { $_ & 0xffff_ffff } @{ $block_ref };
    my @key = map { $_ & 0xffff_ffff } @{ $key_ref };
    my $sumation = $SUMATION & 0xffff_ffff;
    my $delta = $DELTA & 0xffff_ffff;
    for my $i ( 0 .. $self->{rounds}-1 ) {
        $block[1] = ( $block[1] - ( ( ( ( ( ( ( ( $block[0] << 4 ) & 0xffff_ffff ) + $key[2] ) & 0xffff_ffff ) ^ ( ( $block[0] + $sumation ) & 0xffff_ffff ) ) & 0xffff_ffff ) ^ ( ( ( ( $block[0] >> 5 ) & 0xffff_ffff ) + $key[3] ) & 0xffff_ffff ) ) & 0xffff_ffff ) ) & 0xffff_ffff;
        $block[0] = ( $block[0] - ( ( ( ( ( ( ( ( $block[1] << 4 ) & 0xffff_ffff ) + $key[0] ) & 0xffff_ffff ) ^ ( ( $block[1] + $sumation ) & 0xffff_ffff ) ) & 0xffff_ffff ) ^ ( ( ( ( $block[1] >> 5 ) & 0xffff_ffff ) + $key[1] ) & 0xffff_ffff ) ) & 0xffff_ffff ) ) & 0xffff_ffff;
        $sumation = ( $sumation - $delta ) & 0xffff_ffff;
        #printf("\t--> Decrypting block round %d of %d\n", $i + 1, $ROUNDS);
        #printf("\t--> block[0] = %d, block[1] = %d\n", $block[0], $block[1]);
    }
    return \@block;
}

sub key_setup {
    my $key_str = shift;
    croak( sprintf( 'key must be %s bytes long', $KEY_SIZE ) ) if length( $key_str ) != $KEY_SIZE;
    my @key_arr = $key_str =~ /.{4}/g;
    my @tea_key = map { unpack 'N*' } @key_arr;
    return \@tea_key;
}

=head1 SEE ALSO

L<http://www.vader.brad.ac.uk/tea/tea.shtml>

L<Crypt::CBC>

=cut

1;
