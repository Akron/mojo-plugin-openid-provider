package Mojolicious::Plugin::OpenID;
use strict;
use warnings;
use Mojo::Base 'Mojolicious::Plugin';

# Register plugin
sub register {
    my ($plugin, $mojo, $param) = @_;

    $mojo->routes->add_shortcut(
	'openid' => sub {
	    my $route = shift;
	    $route->name('openid');

	    $route->to(
		cb => sub {
		    my $self    = shift;
		    my $mode    = $self->param("openid.mode") || '';
		    my $ns      = $self->param("openid.ns")   || '';
		    my $version = 0;

		    # Debug information:
		    my $log = $mojo->log;
		    $log->debug("-------------------------------");
		    $log->debug(sprintf("Mode: %s", $mode));
		    $log->debug(sprintf("NS: %s", $ns));
		    $log->debug("Current URI: " . $self->req->url);
		    $log->debug("Params: ".Dumper($self->req->params->to_hash));

		    return $self->render('endpoint') unless $mode;
		    
 		    # version 1
		    if (!$ns || (index($ns, 'http://openid.net/signon/1.') == 0)) {
			$version = 1;
		    }

		    # version 2
		    elsif ($ns eq 'http://specs.openid.net/auth/2.0') {
			$version = 2;
		    }
		    		    
		    # Unknown version
		    else {
			return $self->render(
			    'format' => 'text',
			    'data'   => "I don't understand that!",
			    'code'   => 400
			    );
		    };
		    
		    $log->debug(sprintf("Version: %s", $version));
		    $log->debug(sprintf("Method: %s", $self->req->method));

		    if($mode eq 'associate' && $self->req->method eq "POST") {
			my $assoc_type    = $self->param("openid.assoc_type")     || '';
			my $session_type  = $self->param("openid.session_type")   || '';
			
			$log->debug(sprintf("Assoc Type: %s", $assoc_type));
			$log->debug(sprintf("Session Type: %s", $session_type));
			
			if ($assoc_type !~ /^HMAC-SHA(?:1|256)$/) {
			    $self->response_associate_type_error();
			    return;
			};

			unless ($session_type =~ /^DH-SHA(?:1|256)$/ ||
				(($session_type eq 'no-encryption') &&
				 $self->req->base->scheme eq 'https')) {
			    return $self->response_associate_type_error;
			}

			my $secret              = "uaSh2aimunah5ineolauneekoo1ocaethaij8eiraiphoeghee";
			my $secret_expire_age   = 86400 * 14;
			my $secret_gen_interval = 86400;

			my $now = time();
			my $sec_time = $now - ($now % $secret_gen_interval);

			my $nonce = _rand_chars(20);
    
			my $handle = "$now:$nonce";

			# hmac-sha1
			if ($assoc_type eq 'HMAC-SHA1') {
			    $handle .= ":" . substr(hmac_sha1_hex($handle,
								  $secret),
						    0,
						    10);
			}

			# hmac-sha256
			elsif ($assoc_type eq 'HMAC-SHA256') {
			    $handle .= ":" . substr(hmac_sha256_hex($handle,
								    $secret),
						    0,
						    16);
			};

			my $c_sec = $self->_secret_of_handle($handle,
							     type => $assoc_type);

			my $expires = $sec_time + $secret_expire_age;

			my $exp_abs = $expires > 1000000000 ? $expires : $expires + $now;
# Why are local variables declared, when there's a return right afterwards?
			return;
		    };

		    if ($mode eq "check_authentication") {
			return $self->render(
			    'format' => 'text',
			    'data'   => 'to be implemented!',
			    'code' => 400);  
		    }

		    # Maybe with a dollar?
		    elsif ($mode =~ /^checkid_(?:immediate|setup)/) {
			return $self->render(
			    'format' => 'text',
			    'data'   => 'to be implemented!',
			    'code' => 400);  
		    };

		    $log->debug("----------------------");
		    $self->response_mode_unknown_error();
		};




		});
	});
};

sub _rand_chars {
    my $plugin = shift;
    my $length = shift;

    my $chal = "";
    my @digits = ('a'..'z', 'A'..'Z', 0..9);
    for (1..$length) {
        $chal .= $digits[ int(rand(62)) ];
    };
    return $chal;
};

sub _secret_of_handle {
    my $plugin = shift;
    my ($handle, %opts) = @_;

    my $dumb_mode = delete $opts{'dumb'}      || 0;
    my $no_verify = delete $opts{'no_verify'} || 0;
    my $type      = delete $opts{'type'}      || 'HMAC-SHA1';

    my %hmac_functions_hex = (
	'HMAC-SHA1'   => \&hmac_sha1_hex,
	'HMAC-SHA256' => \&hmac_sha256_hex,
	);

    my %hmac_functions = (
	'HMAC-SHA1'   => \&hmac_sha1,
	'HMAC-SHA256' => \&hmac_sha256,
	);

    my %nonce_80_lengths = (
	'HMAC-SHA1'   => 10,
	'HMAC-SHA256' => 16,
	);

    my $nonce_80_len = $nonce_80_lengths{$type};
    my $hmac_function_hex = $hmac_functions_hex{$type} or Carp::croak "No function for $type";
    my $hmac_function = $hmac_functions{$type} or Carp::croak "No function for $type";
    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;

    my ($time, $nonce, $nonce_sig80) = split(/:/, $handle);
    return unless $time =~ /^\d+$/ && $nonce && $nonce_sig80;

    # check_authentication mode only verifies signatures made with
    # dumb (stateless == STLS) handles, so if that caller requests it,
    # don't return the secrets here of non-stateless handles
    return if $dumb_mode && $nonce !~ /^STLS\./;

    my $sec_time = $time - ($time % $plugin->secret_gen_interval);
    my $s_sec = $plugin->_get_server_secret($sec_time)  or return;

    length($nonce)       == ($dumb_mode ? 25 : 20) or return;
    length($nonce_sig80) == $nonce_80_len          or return;

    return unless $no_verify || $nonce_sig80 eq substr($hmac_function_hex->("$time:$nonce", $s_sec), 0, $nonce_80_len);

    return $hmac_function->($handle, $s_sec);
}

sub response_error {
    my $self              = shift;
    my $additional_params = shift;

    my $params = Mojo::Parameters->new(%{$additional_params});
    $params->param('ns' => 'http://specs.openid.net/auth/2.0');
    $params->param('openid.ns' => 'Type ');
    $params->param('contact'   => 'info@stephan-jauernick.de');
    $params->param('reference' => 'Mail me!');
 
    my $string = $self->hash_to_kv($params->to_hash); 
    $self->app->log->debug(sprintf("Response(Error): %s", $string ));
    
    return $self->render('code'   => 400,
			 'format' => 'text',
			 'data'   => "$string");
};

sub response_associate_type_error { 
    my $self              = shift;
    my $additional_params = shift;

    $additional_params    = $self->response_associate($additional_params);

    my $params = Mojo::Parameters->new(%{$additional_params});

    $params->param('error'        => 'Type not supported!');
    $params->param('error_code'   => 'unsupported-type');
    $params->param('session_type' => 'DH-SHA256');
    
    $self->response_error($params->to_hash);
    return;
};

sub response_associate {
    my $self              = shift;
    my $additional_params = shift;

    my $params = Mojo::Parameters->new(%{$additional_params});
    $params->param('assoc_type'   => $self->param("openid.assoc_type"));
    $params->param('session_type' => $self->param("openid.session_type"));
    
    return $params->to_hash;
};

sub response_mode_unknown_error {
    my $self              = shift;
    my $additional_params = shift;

    my $params = Mojo::Parameters->new(%{$additional_params});
    
    $params->param('error'        => 'Mode not supported!');
    $params->param('error_code'   => 'unsupported-mode');

    $self->response_error($params->to_hash);
    return;
};

sub response_success {
    my $self              = shift;
    my $additional_params = shift;

    my $params = Mojo::Parameters->new($additional_params);
    $params->param('ns' => 'http://specs.openid.net/auth/2.0');
    $params->param('contact'   => 'info@stephan-jauernick.de');
    $params->param('reference' => 'Mail me!');

    my $string = $self->hash_to_kv($params->to_hash);
    $self->app->log->debug(sprintf("Response(Success): %s", $string ));

    return $self->render('format' => 'text',
			 'code' => 200,
			 'data' => $string);
};

sub hash_to_kv {
    my ($self, $hash) = @_;
    my $output;
    $output = join(
	"\n",
        map( sprintf( q{%s:%s}, $_, $hash->{$_} ),
	     sort keys %{ $hash } )
	)."\n";
    return $output;
};




1;
