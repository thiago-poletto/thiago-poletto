/ *
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2017 pooler
 *
* Este programa é um software livre; você pode redistribuí-lo e / ou modificá-lo
 * sob os termos da GNU General Public License conforme publicada pela Free
* Software Foundation; tanto a versão 2 da Licença, ou (por sua opção)
* qualquer versão posterior. Veja COPIANDO para mais detalhes.
 * /

# inclui  " cpuminer-config.h "
# define  _GNU_SOURCE

# inclui  < stdio.h >
# inclui  < stdlib.h >
# inclui  < string.h >
# inclua  < stdbool.h >
# inclua  < inttypes.h >
# inclui  < unistd.h >
# inclui  < sys / time.h >
# inclui  < time.h >
# ifdef WIN32
# inclui  < windows.h >
mais #
# inclui  < errno.h >
# inclui  < signal.h >
# inclui  < sys / resource.h >
# if HAVE_SYS_SYSCTL_H
# inclui  < sys / types.h >
# if HAVE_SYS_PARAM_H
# inclui  < sys / param.h >
# endif
# inclui  < sys / sysctl.h >
# endif
# endif
# inclua  < jansson.h >
# inclua  < curl / curl.h >
# inclui  " compat.h "
# inclui  " miner.h "

# define  PROGRAM_NAME 		" minerd "
# define  LP_SCANTIME 		60

# ifdef __linux / * Política específica do Linux e gerenciamento de afinidade * /
# inclui  < sched.h >
static  inline  void  drop_policy ( void )
{
	parâmetro de struct sched_param;
	param. sched_priority = 0 ;

# ifdef SCHED_IDLE
	if ( improvável ( sched_setscheduler ( 0 , SCHED_IDLE, & param) == - 1 ))
# endif
# ifdef SCHED_BATCH
		sched_setscheduler ( 0 , SCHED_BATCH, & param);
# endif
}

static  inline  void  affine_to_cpu ( int id, int cpu)
{
	cpu_set_t set;

	CPU_ZERO (& set);
	CPU_SET (cpu, & set);
	sched_setaffinity ( 0 , sizeof (set), & set);
}
# elif defined (__ FreeBSD__) / * Política específica do FreeBSD e gerenciamento de afinidade * /
# inclui  < sys / cpuset.h >
static  inline  void  drop_policy ( void )
{
}

static  inline  void  affine_to_cpu ( int id, int cpu)
{
	cpuset_t set;
	CPU_ZERO (& set);
	CPU_SET (cpu, & set);
	cpuset_setaffinity (CPU_LEVEL_WHICH, CPU_WHICH_TID, - 1 , sizeof ( cpuset_t ), & set);
}
mais #
static  inline  void  drop_policy ( void )
{
}

static  inline  void  affine_to_cpu ( int id, int cpu)
{
}
# endif
		
enum workio_commands {
	WC_GET_WORK,
	WC_SUBMIT_WORK,
};

struct workio_cmd {
	enum workio_commands cmd;
	struct thr_info * thr;
	união {
		estrutura trabalho * trabalho;
	} você;
};

enum algos {
	ALGO_SCRYPT,		 / * scrypt (1024,1,1) * /
	ALGO_SHA256D,		 / * SHA-256d * /
};

static  const  char * algo_names [] = {
	[ALGO_SCRYPT] = " criptografar " ,
	[ALGO_SHA256D] = " sha256d " ,
};

bool opt_debug = false ;
bool opt_protocol = false ;
 bool estático opt_benchmark = false ;
bool opt_redirect = true ;
bool want_longpoll = true ;
bool have_longpoll = false ;
bool have_gbt = true ;
bool allow_getwork = true ;
bool want_stratum = true ;
bool have_stratum = false ;
bool use_syslog = false ;
estático  bool opt_background = false ;
 bool estático opt_quiet = false ;
static  int opt_retries = - 1 ;
static  int opt_fail_pause = 30 ;
int opt_timeout = 0 ;
static  int opt_scantime = 5 ;
 enum algos estático opt_algo = ALGO_SCRYPT;
static  int opt_scrypt_n = 1024 ;
static  int opt_n_threads;
static  int num_processors;
static  char * rpc_url;
static  char * rpc_userpass;
 char estático * rpc_user, * rpc_pass;
static  int pk_script_size;
estático  não assinado  char pk_script [ 42 ];
 char estático coinbase_sig [ 101 ] = " " ;
char * opt_cert;
char * opt_proxy;
long opt_proxy_type;
struct thr_info * thr_info;
static  int work_thr_id;
int longpoll_thr_id = - 1 ;
int stratum_thr_id = - 1 ;
struct work_restart * work_restart = NULL ;
static  struct stratum_ctx stratum;

pthread_mutex_t applog_lock;
static  pthread_mutex_t stats_lock;

estático  sem sinal  longo aceite_count = 0L ;
estático  sem sinal  longo rejeitado_count = 0L ;
static  double * thr_hashrates;

# ifdef HAVE_GETOPT_LONG
# include  < getopt.h >
mais #
opção de estrutura {
	const  char * name;
	int has_arg;
	int * flag;
	int val;
};
# endif

static  char  const usage [] = " \
Uso: " PROGRAM_NAME " [OPTIONS] \ n \
Opções: \ n \
  -a, --algo = ALGO especifica o algoritmo a ser usado \ n \
                          scrypt scrypt (1024, 1, 1) (padrão) \ n \
                          scrypt: N scrypt (N, 1, 1) \ n \
                          sha256d SHA-256d \ n \
  -o, --url = URL URL do servidor de mineração \ n \
  -O, --userpass = U: P nome de usuário: par de senha para servidor de mineração \ n \
  -u, --user = nome de usuário USERNAME para o servidor de mineração \ n \
  -p, --pass = senha PASSWORD para servidor de mineração \ n \
      --cert = Certificado FILE para servidor de mineração usando SSL \ n \
  -x, --proxy = [PROTOCOL: //] HOST [: PORT] conectar por meio de um proxy \ n \
  -t, --threads = N número de threads de mineração (padrão: número de processadores) \ n \
  -r, --retries = N número de vezes para tentar novamente se uma chamada de rede falhar \ n \
                          (padrão: tentar novamente indefinidamente) \ n \
  -R, --retry-pause = N tempo para fazer uma pausa entre as novas tentativas, em segundos (padrão: 30) \ n \
  -T, --timeout = N tempo limite para sondagem longa, em segundos (padrão: nenhum) \ n \
  -s, --scantime = N limite superior no tempo gasto na verificação do trabalho atual quando \ n \
                          a sondagem longa não está disponível, em segundos (padrão: 5) \ n \
      --coinbase-addr = Endereço de pagamento ADDR para mineração solo \ n \
      --coinbase-sig = dados de TEXTO para inserir na coinbase quando possível \ n \
      --no-longpoll desativa o suporte para long polling \ n \
      --no-getwork desativa o suporte getwork \ n \
      --no-gbt desativa o suporte getblocktemplate \ n \
      --no-stratum desativa o suporte X-Stratum \ n \
      --no-redirect ignorar solicitações para alterar a URL do servidor de mineração \ n \
  -q, --quiet desativa a saída do hashmeter por thread \ n \
  -D, --debug habilitar saída de depuração \ n \
  -P, --protocol-dump despejo detalhado de atividades de nível de protocolo \ n "
# ifdef HAVE_SYSLOG_H
" \
  -S, --syslog usa log do sistema para mensagens de saída \ n "
# endif
# ifndef WIN32
" \
  -B, --background executa o minerador em segundo plano \ n "
# endif
" \
      --benchmark executado no modo de benchmark offline \ n \
  -c, --config = FILE carrega um arquivo de configuração no formato JSON \ n \
  -V, --version exibe informações da versão e sai \ n \
  -h, --help exibe este texto de ajuda e sai \ n \
" ;

static  char  const short_options [] =
# ifndef WIN32
	" B "
# endif
# ifdef HAVE_SYSLOG_H
	" S "
# endif
	" a: c: Dhp: Px: qr: R: s: t: T: o: u: O: V " ;

 opção de estrutura estática const options [] = {
	{ " algo " , 1 , NULL , ' a ' },
# ifndef WIN32
	{ " fundo " , 0 , NULL , ' B ' },
# endif
	{ " benchmark " , 0 , NULL , 1005 },
	{ " cert " , 1 , NULL , 1001 },
	{ " coinbase-addr " , 1 , NULL , 1013 },
	{ " coinbase-sig " , 1 , NULL , 1015 },
	{ " config " , 1 , NULL , ' c ' },
	{ " depurar " , 0 , NULL , ' D ' },
	{ " ajuda " , 0 , NULL , ' h ' },
	{ " no-gbt " , 0 , NULL , 1011 },
	{ " no-getwork " , 0 , NULL , 1010 },
	{ " no-longpoll " , 0 , NULL , 1003 },
	{ " sem redirecionamento " , 0 , NULL , 1009 },
	{ " sem estrato " , 0 , NULL , 1007 },
	{ " passar " , 1 , NULL , ' p ' },
	{ " despejo de protocolo " , 0 , NULL , ' P ' },
	{ " proxy " , 1 , NULL , ' x ' },
	{ " quieto " , 0 , NULL , ' q ' },
	{ " tentativas " , 1 , NULL , ' r ' },
	{ " retry-pause " , 1 , NULL , ' R ' },
	{ " scantime " , 1 , NULL , ' s ' },
# ifdef HAVE_SYSLOG_H
	{ " syslog " , 0 , NULL , ' S ' },
# endif
	{ " threads " , 1 , NULL , ' t ' },
	{ " tempo limite " , 1 , NULL , ' T ' },
	{ " url " , 1 , NULL , ' o ' },
	{ " usuário " , 1 , NULL , ' u ' },
	{ " userpass " , 1 , NULL , ' O ' },
	{ " versão " , 0 , NULL , ' V ' },
	{ 0 , 0 , 0 , 0 }
};

struct work {
	dados uint32_t [ 32 ];
	uint32_t target [ 8 ];

	altura interna ;
	char * txs;
	char * workid;

	char * job_id;
	size_t xnonce2_len;
	unsigned  char * xnonce2;
};

 trabalho de estrutura estática g_work;
static  time_t g_work_time;
static  pthread_mutex_t g_work_lock;
estático  bool submit_old = false ;
static  char * lp_id;

static  inline  void  work_free ( struct work * w)
{
	livre (w-> txs );
	grátis (w-> workid );
	livre (w-> job_id );
	livre (w-> xnonce2 );
}

static  inline  void  work_copy ( struct work * dest, const  struct work * src)
{
	memcpy (dest, src, sizeof ( struct work));
	if (src-> txs )
		dest-> txs = strdup (src-> txs );
	if (src-> workid )
		dest-> id de trabalho = strdup (src-> id de trabalho );
	if (src-> job_id )
		dest-> job_id = strdup (src-> job_id );
	if (src-> xnonce2 ) {
		dest-> xnonce2 = malloc (src-> xnonce2_len );
		memcpy (dest-> xnonce2 , src-> xnonce2 , src-> xnonce2_len );
	}
}

static  bool  jobj_binary ( const  json_t * obj, const  char * key,
			void * buf, size_t buflen)
{
	const  char * hexstr;
	json_t * tmp;

	tmp = json_object_get (obj, chave);
	if ( improvável (! tmp)) {
		applog (LOG_ERR, " chave JSON ' % s ' não encontrada " , chave);
		return  false ;
	}
	hexstr = json_string_value (tmp);
	if ( improvável (! hexstr)) {
		applog (LOG_ERR, " chave JSON ' % s ' não é uma string " , chave);
		return  false ;
	}
	if (! hex2bin (buf, hexstr, buflen))
		return  false ;

	return  true ;
}

estático  bool  work_decode ( const  json_t * val, struct work * work)
{
	int i;

	if ( improvável (! jobj_binary (val, " dados " , trabalho-> dados , sizeof (trabalho-> dados )))) {
		applog (LOG_ERR, " dados inválidos JSON " );
		goto err_out;
	}
	if ( improvável (! jobj_binary (val, " target " , work-> target , sizeof (work-> target )))) {
		applog (LOG_ERR, " alvo inválido JSON " );
		goto err_out;
	}

	para (i = 0 ; i < ARRAY_SIZE (trabalho-> dados ); i ++)
		trabalho-> dados [i] = le32dec (trabalho-> dados + i);
	para (i = 0 ; i < ARRAY_SIZE (trabalho-> destino ); i ++)
		trabalho-> alvo [i] = le32dec (trabalho-> alvo + i);

	return  true ;

err_out:
	return  false ;
}

static  bool  gbt_work_decode ( const  json_t * val, struct work * work)
{
	int i, n;
	versão uint32_t , curtime, bits;
	uint32_t prevhash [ 8 ];
	uint32_t target [ 8 ];
	int cbtx_size;
	 char não assinado * cbtx = NULL ;
	 char não assinado * tx = NULL ;
	int tx_count, tx_size;
	 char não assinado txc_vi [ 9 ];
	 char não assinado (* merkle_tree) [ 32 ] = NULL ;
	bool coinbase_append = false ;
	bool submit_coinbase = false ;
	bool segwit = false ;
	json_t * tmp, * txa;
	bool rc = falso ;

	tmp = json_object_get (val, " regras " );
	if (tmp && json_is_array (tmp)) {
		n = json_array_size (tmp);
		para (i = 0 ; i <n; i ++) {
			const  char * s = json_string_value ( json_array_get (tmp, i));
			se (! s)
				continue ;
			if (! strcmp (s, " segwit " ) ||! strcmp (s, " ! segwit " ))
				segwit = true ;
		}
	}

	tmp = json_object_get (val, " mutável " );
	if (tmp && json_is_array (tmp)) {
		n = json_array_size (tmp);
		para (i = 0 ; i <n; i ++) {
			const  char * s = json_string_value ( json_array_get (tmp, i));
			se (! s)
				continue ;
			if (! strcmp (s, " coinbase / append " ))
				coinbase_append = true ;
			else  if (! strcmp (s, " submit / coinbase " ))
				submit_coinbase = true ;
		}
	}

	tmp = json_object_get (val, " altura " );
	if (! tmp ||! json_is_integer (tmp)) {
		applog (LOG_ERR, " altura inválida JSON " );
		goto out;
	}
	trabalho-> altura = json_integer_value (tmp);

	tmp = json_object_get (val, " versão " );
	if (! tmp ||! json_is_integer (tmp)) {
		applog (LOG_ERR, " versão inválida JSON " );
		goto out;
	}
	versão = json_integer_value (tmp);

	if ( improvável (! jobj_binary (val, " previousblockhash " , prevhash, sizeof (prevhash)))) {
		applog (LOG_ERR, " JSON invalid previousblockhash " );
		goto out;
	}

	tmp = json_object_get (val, " curtime " );
	if (! tmp ||! json_is_integer (tmp)) {
		applog (LOG_ERR, " curtime inválido JSON " );
		goto out;
	}
	curtime = json_integer_value (tmp);

	if ( improvável (! jobj_binary (val, " bits " , & bits, sizeof (bits)))) {
		applog (LOG_ERR, " bits inválidos JSON " );
		goto out;
	}

	/ * encontrar contagem e tamanho das transações * /
	txa = json_object_get (val, " transações " );
	if (! txa ||! json_is_array (txa)) {
		applog (LOG_ERR, " JSON transações inválidas " );
		goto out;
	}
	tx_count = json_array_size (txa);
	tx_size = 0 ;
	para (i = 0 ; i <tx_count; i ++) {
		const  json_t * tx = json_array_get (txa, i);
		const  char * tx_hex = json_string_value ( json_object_get (tx, " dados " ));
		if (! tx_hex) {
			applog (LOG_ERR, " JSON transações inválidas " );
			goto out;
		}
		tx_size + = strlen (tx_hex) / 2 ;
	}

	/ * build coinbase transaction * /
	tmp = json_object_get (val, " coinbasetxn " );
	if (tmp) {
		const  char * cbtx_hex = json_string_value ( json_object_get (tmp, " dados " ));
		cbtx_size = cbtx_hex? strlen (cbtx_hex) / 2 : 0 ;
		cbtx = malloc (cbtx_size + 100 );
		if (cbtx_size < 60 ||! hex2bin (cbtx, cbtx_hex, cbtx_size)) {
			applog (LOG_ERR, " JSON coinbasetxn inválido " );
			goto out;
		}
	} else {
		int64_t cbvalue;
		if (! pk_script_size) {
			if (allow_getwork) {
				applog (LOG_INFO, " Nenhum endereço de pagamento fornecido, mudando para rede " );
				have_gbt = false ;
			} mais
				applog (LOG_ERR, " Nenhum endereço de pagamento fornecido " );
			goto out;
		}
		tmp = json_object_get (val, " coinbasevalue " );
		if (! tmp ||! json_is_number (tmp)) {
			applog (LOG_ERR, " JSON inválido coinbasevalue " );
			goto out;
		}
		cbvalue = json_is_integer (tmp)? json_integer_value (tmp): json_number_value (tmp);
		cbtx = malloc ( 256 );
		le32enc (( uint32_t *) cbtx, 1 ); / * versão * /
		cbtx [ 4 ] = 1 ; / * no balcão * /
		memset (cbtx + 5 , 0x00 , 32 ); / * hash txout anterior * /
		le32enc (( uint32_t *) (cbtx + 37 ), 0xffffffff ); / * índice anterior txout * /
		cbtx_size = 43 ;
		/ * BIP 34: altura em coinbase * /
		if (trabalho-> altura > = 1 && trabalho-> altura <= 16 ) {
			/ * Use OP_1-OP_16 para se adequar à implementação do Bitcoin. * /
			cbtx [ 42 ] = trabalho-> altura + 0x50 ;
			cbtx [cbtx_size ++] = 0x00 ; / * OP_0; pads para 2 bytes * /
		} else {
			para (n = trabalho-> altura ; n; n >> = 8 ) {
				cbtx [cbtx_size ++] = n & 0xff ;
				if (n < 0x100 && n> = 0x80 )
					cbtx [cbtx_size ++] = 0 ;
			}
			cbtx [ 42 ] = cbtx_size - 43 ;
		}
		cbtx [ 41 ] = cbtx_size - 42 ; / * comprimento do scriptig * /
		le32enc (( uint32_t *) (cbtx + cbtx_size), 0xffffffff ); / * sequência * /
		cbtx_size + = 4 ;
		cbtx [cbtx_size ++] = segwit? 2 : 1 ; / * out-counter * /
		le32enc (( uint32_t *) (cbtx + cbtx_size), ( uint32_t ) cbvalue); / * valor * /
		le32enc (( uint32_t *) (cbtx + cbtx_size + 4 ), cbvalue >> 32 );
		cbtx_size + = 8 ;
		cbtx [cbtx_size ++] = pk_script_size; / * comprimento do script txout * /
		memcpy (cbtx + cbtx_size, pk_script, pk_script_size);
		cbtx_size + = pk_script_size;
		if (segwit) {
			 char unsigned (* wtree) [ 32 ] = calloc (tx_count + 2 , 32 );
			memset (cbtx + cbtx_size, 0 , 8 ); / * valor * /
			cbtx_size + = 8 ;
			cbtx [cbtx_size ++] = 38 ; / * comprimento do script txout * /
			cbtx [cbtx_size ++] = 0x6a ; / * txout-script * /
			cbtx [cbtx_size ++] = 0x24 ;
			cbtx [cbtx_size ++] = 0xaa ;
			cbtx [cbtx_size ++] = 0x21 ;
			cbtx [cbtx_size ++] = 0xa9 ;
			cbtx [cbtx_size ++] = 0xed ;
			para (i = 0 ; i <tx_count; i ++) {
				const  json_t * tx = json_array_get (txa, i);
				const  json_t * hash = json_object_get (tx, " hash " );
				if (! hash ||! hex2bin (wtree [ 1 + i], json_string_value (hash), 32 )) {
					applog (LOG_ERR, " hash de transação inválida JSON " );
					grátis (wtree);
					goto out;
				}
				memrev (wtree [ 1 + i], 32 );
			}
			n = tx_count + 1 ;
			enquanto (n> 1 ) {
				if (n% 2 )
					memcpy (wtree [n], wtree [n- 1 ], 32 );
				n = (n + 1 ) / 2 ;
				para (i = 0 ; i <n; i ++)
					sha256d (wtree [i], wtree [ 2 * i], 64 );
			}
			memset (wtree [ 1 ], 0 , 32 );  / * valor reservado para testemunha = 0 * /
			sha256d (cbtx + cbtx_size, wtree [ 0 ], 64 );
			cbtx_size + = 32 ;
			grátis (wtree);
		}
		le32enc (( uint32_t *) (cbtx + cbtx_size), 0 ); / * tempo de bloqueio * /
		cbtx_size + = 4 ;
		coinbase_append = true ;
	}
	if (coinbase_append) {
		 char não assinado xsig [ 100 ];
		int xsig_len = 0 ;
		if (* coinbase_sig) {
			n = strlen (coinbase_sig);
			if (cbtx [ 41 ] + xsig_len + n <= 100 ) {
				memcpy (xsig + xsig_len, coinbase_sig, n);
				xsig_len + = n;
			} else {
				applog (LOG_WARNING, "A assinatura não cabe no coinbase, pulando " );
			}
		}
		tmp = json_object_get (val, " coinbaseaux " );
		if (tmp && json_is_object (tmp)) {
			void * iter = json_object_iter (tmp);
			while (iter) {
				 char buf sem sinal [ 100 ];
				const  char * s = json_string_value ( json_object_iter_value (iter));
				n = s? strlen (s) / 2 : 0 ;
				if (! s || n> 100 ||! hex2bin (buf, s, n)) {
					applog (LOG_ERR, " JSON inválido coinbaseaux " );
					pausa ;
				}
				if (cbtx [ 41 ] + xsig_len + n <= 100 ) {
					memcpy (xsig + xsig_len, buf, n);
					xsig_len + = n;
				}
				iter = json_object_iter_next (tmp, iter);
			}
		}
		if (xsig_len) {
			 char não assinado * ssig_end = cbtx + 42 + cbtx [ 41 ];
			int push_len = cbtx [ 41 ] + xsig_len < 76 ? 1 :
			               cbtx [ 41 ] + 2 + xsig_len> 100 ? 0 : 2 ;
			n = xsig_len + push_len;
			memmove (ssig_end + n, ssig_end, cbtx_size - 42 - cbtx [ 41 ]);
			cbtx [ 41 ] + = n;
			if (push_len == 2 )
				* (ssig_end ++) = 0x4c ; / * OP_PUSHDATA1 * /
			if (push_len)
				* (ssig_end ++) = xsig_len;
			memcpy (ssig_end, xsig, xsig_len);
			cbtx_size + = n;
		}
	}

	n = varint_encode (txc_vi, 1 + tx_count);
work- 	> txs = malloc ( 2 * (n + cbtx_size + tx_size) + 1 );
	bin2hex (trabalho-> txs , txc_vi, n);
	bin2hex (trabalho-> txs + 2 * n, cbtx, cbtx_size);
	char * txs_end = trabalho-> txs + strlen (trabalho-> txs );

	/ * gerar raiz merkle * /
	merkle_tree = malloc ( 32 * (( 1 + tx_count + 1 ) & ~ 1 ));
	size_t tx_buf_size = 32 * 1024 ;
	tx = malloc (tx_buf_size);
	sha256d (merkle_tree [ 0 ], cbtx, cbtx_size);
	para (i = 0 ; i <tx_count; i ++) {
		tmp = json_array_get (txa, i);
		const  char * tx_hex = json_string_value ( json_object_get (tmp, " dados " ));
		const  size_t tx_hex_len = tx_hex? strlen (tx_hex): 0 ;
		const  int tx_size = tx_hex_len / 2 ;
		if (segwit) {
			const  char * txid = json_string_value ( json_object_get (tmp, " txid " ));
			if (! txid ||! hex2bin (merkle_tree [ 1 + i], txid, 32 )) {
				applog (LOG_ERR, " JSON inválido transação txid " );
				goto out;
			}
			memrev (merkle_tree [ 1 + i], 32 );
		} else {
			if (tx_size> tx_buf_size) {
				livre (tx);
				tx_buf_size = tx_size * 2 ;
				tx = malloc (tx_buf_size);
			}
			if (! tx_hex ||! hex2bin (tx, tx_hex, tx_size)) {
				applog (LOG_ERR, " JSON transações inválidas " );
				goto out;
			}
			sha256d (merkle_tree [ 1 + i], tx, tx_size);
		}
		if (! submit_coinbase) {
			strcpy (txs_end, tx_hex);
			txs_end + = tx_hex_len;
		}
	}
	livre (tx); tx = NULL ;
	n = 1 + tx_count;
	enquanto (n> 1 ) {
		if (n% 2 ) {
			memcpy (merkle_tree [n], merkle_tree [n- 1 ], 32 );
			++ n;
		}
		n / = 2 ;
		para (i = 0 ; i <n; i ++)
			sha256d (merkle_tree [i], merkle_tree [ 2 * i], 64 );
	}

	/ * montar cabeçalho do bloco * /
	trabalho-> dados [ 0 ] = swab32 (versão);
	para (i = 0 ; i < 8 ; i ++)
		trabalho-> dados [ 8 - i] = le32dec (prevhash + i);
	para (i = 0 ; i < 8 ; i ++)
		trabalho-> dados [ 9 + i] = be32dec (( uint32_t *) merkle_tree [ 0 ] + i);
	trabalho-> dados [ 17 ] = swab32 (curtime);
	trabalho-> dados [ 18 ] = le32dec (& bits);
	memset (trabalho-> dados + 19 , 0x00 , 52 );
	trabalho-> dados [ 20 ] = 0x80000000 ;
	trabalho-> dados [ 31 ] = 0x00000280 ;

	if ( improvável (! jobj_binary (val, " target " , target, sizeof (target)))) {
		applog (LOG_ERR, " alvo inválido JSON " );
		goto out;
	}
	para (i = 0 ; i < ARRAY_SIZE (trabalho-> destino ); i ++)
		trabalho-> alvo [ 7 - i] = be32dec (alvo + i);

	tmp = json_object_get (val, " workid " );
	if (tmp) {
		if (! json_is_string (tmp)) {
			applog (LOG_ERR, " JSON inválido workid " );
			goto out;
		}
work- 		> workid = strdup ( json_string_value (tmp));
	}

	/ * Sondagem longa * /
	tmp = json_object_get (val, " longpollid " );
	if (want_longpoll && json_is_string (tmp)) {
		livre (lp_id);
		lp_id = strdup ( json_string_value (tmp));
		if (! have_longpoll) {
			char * lp_uri;
			tmp = json_object_get (val, " longpolluri " );
			lp_uri = strdup ( json_is_string (tmp)? json_string_value (tmp): rpc_url);
			have_longpoll = true ;
			tq_push (thr_info [longpoll_thr_id]. q , lp_uri);
		}
	}

	rc = verdadeiro ;

Fora:
	livre (tx);
	livre (cbtx);
	livre (merkle_tree);
	return rc;
}

static  void  share_result ( int result, const  char * reason)
{
	char s [ 345 ];
	hashrate duplo ;
	int i;

	hashrate = 0 .;
	pthread_mutex_lock (& stats_lock);
	para (i = 0 ; i <opt_n_threads; i ++)
		hashrate + = thr_hashrates [i];
	resultado? contagem_aceitada ++: contagem_ rejeitada ++;
	pthread_mutex_unlock (& stats_lock);
	
	sprintf (s, hashrate> = 1e6 ? " % .0f " : " % .2f " , 1e-3 * hashrate);
	applog (LOG_INFO, " aceito: % lu / % lu ( % .2f %% ), % s khash / s % s " ,
		   aceita_conta,
		   aceita_conta + rejeitada_conta,
		   100 . * aceita_conta / (aceita_conta + rejeitada),
		   s,
		   resultado? " (yay !!!) " : " (booooo) " );

	if (opt_debug && reason)
		applog (LOG_DEBUG, " DEBUG: motivo da rejeição: % s " , motivo);
}

static  bool  submit_upstream_work (CURL * curl, struct work * work)
{
	json_t * val, * res, * reason;
	char data_str [ 2 * sizeof ( work- > data ) + 1 ];
	char s [ 345 ];
	int i;
	bool rc = falso ;

	/ * passar se o hash anterior não for o hash anterior atual * /
	if (! submit_old && memcmp ( work- > data + 1 , g_work. data + 1 , 32 )) {
		if (opt_debug)
			applog (LOG_DEBUG, " DEBUG: trabalho obsoleto detectado, descartando " );
		return  true ;
	}

	if (have_stratum) {
		uint32_t ntime, nonce;
		char ntimestr [ 9 ], noncestr [ 9 ], * xnonce2str, * req;

		le32enc (& ntime, work-> data [ 17 ]);
		le32enc (& nonce, trabalho-> dados [ 19 ]);
		bin2hex (ntimestr, ( const  unsigned  char *) (& ntime), 4 );
		bin2hex (noncestr, ( const  unsigned  char *) (& nonce), 4 );
		xnonce2str = abin2hex (trabalho-> xnonce2 , trabalho-> xnonce2_len );
		req = malloc ( 256 + strlen (rpc_user) + strlen (trabalho-> job_id ) + 2 * trabalho-> xnonce2_len );
		sprintf (req,
			" { \" método \ " : \" mining.submit \ " , \" params \ " : [ \" % s \ " , \" % s \ " , \" % s \ " , \" % s \ " , \ " % s \" ], \ " id \" : 4} " ,
			rpc_user, work-> job_id , xnonce2str, ntimestr, noncestr);
		livre (xnonce2str);

		rc = stratum_send_line (& stratum, req);
		livre (req);
		if ( improvável (! rc)) {
			applog (LOG_ERR, " submit_upstream_work stratum_send_line falhou " );
			goto out;
		}
	} else  if ( work- > txs ) {
		char * req;

		para (i = 0 ; i < ARRAY_SIZE (trabalho-> dados ); i ++)
			be32enc (trabalho-> dados + i, trabalho-> dados [i]);
		bin2hex (data_str, ( unsigned  char *) work-> data , 80 );
		if ( work- > workid ) {
			char * params;
			val = json_object ();
			json_object_set_new (val, " workid " , json_string ( work- > workid ));
			params = json_dumps (val, 0 );
			json_decref (val);
			req = malloc ( 128 + 2 * 80 + strlen (trabalho-> txs ) + strlen (params));
			sprintf (req,
				" { \" método \ " : \" submitblock \ " , \" params \ " : [ \" % s% s \ " , % s ], \" id \ " : 1} \ r \ n " ,
				data_str, work-> txs , params);
			grátis (params);
		} else {
			req = malloc ( 128 + 2 * 80 + strlen (trabalho-> txs ));
			sprintf (req,
				" { \" método \ " : \" submitblock \ " , \" params \ " : [ \" % s% s \ " ], \" id \ " : 1} \ r \ n " ,
				data_str, work-> txs );
		}
		val = json_rpc_call (curl, rpc_url, rpc_userpass, req, NULL , 0 );
		livre (req);
		if ( improvável (! val)) {
			applog (LOG_ERR, " submit_upstream_work json_rpc_call falhou " );
			goto out;
		}

		res = json_object_get (val, " resultado " );
		if ( json_is_object (res)) {
			char * res_str;
			bool sumres = false ;
			void * iter = json_object_iter (res);
			while (iter) {
				if ( json_is_null ( json_object_iter_value (iter))) {
					sumres = verdadeiro ;
					pausa ;
				}
				iter = json_object_iter_next (res, iter);
			}
			res_str = json_dumps (res, 0 );
			share_result (sumres, res_str);
			livre (res_str);
		} mais
			share_result ( json_is_null (res), json_string_value (res));

		json_decref (val);
	} else {
		/ * construir string hexadecimal * /
		para (i = 0 ; i < ARRAY_SIZE (trabalho-> dados ); i ++)
			le32enc (trabalho-> dados + i, trabalho-> dados [i]);
		bin2hex (data_str, ( unsigned  char *) work-> data , sizeof (work-> data ));

		/ * construir solicitação JSON-RPC * /
		sprintf (s,
			" { \" método \ " : \" rede \ " , \" params \ " : [ \" % s \ " ], \" id \ " : 1} \ r \ n " ,
			data_str);

		/ * emitir solicitação JSON-RPC * /
		val = json_rpc_call (curl, rpc_url, rpc_userpass, s, NULL , 0 );
		if ( improvável (! val)) {
			applog (LOG_ERR, " submit_upstream_work json_rpc_call falhou " );
			goto out;
		}

		res = json_object_get (val, " resultado " );
		razão = json_object_get (val, " rejeitar razão " );
		share_result ( json_is_true (res), motivo? json_string_value (motivo): NULL );

		json_decref (val);
	}

	rc = verdadeiro ;

Fora:
	return rc;
}

static  const  char * getwork_req =
	" { \" método \ " : \" rede \ " , \" params \ " : [], \" id \ " : 0} \ r \ n " ;

# define  GBT_CAPABILITIES  " [ \" coinbasetxn \ " , \" coinbasevalue \ " , \" longpoll \ " , \" workid \ " ] "
# define  GBT_RULES  " [ \" segwit \ " ] "

static  const  char * gbt_req =
	" { \" método \ " : \" getblocktemplate \ " , \" params \ " : [{ \" capacidades \ " : "
	GBT_CAPABILITIES " , \" regras \ " : " GBT_RULES " }], \" id \ " : 0} \ r \ n " ;
static  const  char * gbt_lp_req =
	" { \" método \ " : \" getblocktemplate \ " , \" params \ " : [{ \" capacidades \ " : "
	GBT_CAPABILITIES " , \" regras \ " : " GBT_RULES " , \" longpollid \ " : \" % s \ " }], \" id \ " : 0} \ r \ n " ;

static  bool  get_upstream_work (CURL * curl, struct work * work)
{
	json_t * val;
	int err;
	bool rc;
	struct  timeval tv_start, tv_end, diff;

começar:
	gettimeofday (& tv_start, NULL );
	val = json_rpc_call (curl, rpc_url, rpc_userpass,
			    have_gbt? gbt_req: getwork_req,
			    & errar, have_gbt? JSON_RPC_QUIET_404: 0 );
	gettimeofday (& tv_end, NULL );

	if (have_stratum) {
		if (val)
			json_decref (val);
		return  true ;
	}

	if (! have_gbt &&! allow_getwork) {
		applog (LOG_ERR, " Nenhum protocolo utilizável " );
		if (val)
			json_decref (val);
		return  false ;
	}

	if (have_gbt && allow_getwork &&! val && err == CURLE_OK) {
		applog (LOG_INFO, " getblocktemplate falhou, retrocedendo para getwork " );
		have_gbt = false ;
		goto start;
	}

	if (! val)
		return  false ;

	if (have_gbt) {
		rc = gbt_work_decode ( json_object_get (val, " resultado " ), trabalho);
		if (! have_gbt) {
			json_decref (val);
			goto start;
		}
	} mais
		rc = work_decode ( json_object_get (val, " resultado " ), trabalho);

	if (opt_debug && rc) {
		timeval_subtract (& diff, & tv_end, & tv_start);
		applog (LOG_DEBUG, " DEBUG: novo trabalho em % d ms " ,
		       diff. tv_sec * 1000 + dif. tv_usec / 1000 );
	}

	json_decref (val);

	return rc;
}

static  void  workio_cmd_free ( struct workio_cmd * wc)
{
	if (! wc)
		retorno ;

	switch (wc-> cmd ) {
	case WC_SUBMIT_WORK:
		work_free (wc-> u . work );
		grátis (wc-> u . trabalho );
		pausa ;
	padrão : / * não fazer nada * /
		pausa ;
	}

	memset (wc, 0 , sizeof (* wc));	/ * veneno * /
	grátis (wc);
}

static  bool  workio_get_work ( struct workio_cmd * wc, CURL * curl)
{
	struct work * ret_work;
	falhas internas = 0 ;

	ret_work = calloc ( 1 , sizeof (* ret_work));
	if (! ret_work)
		return  false ;

	/ * obter novo trabalho do bitcoin via JSON-RPC * /
	while (! get_upstream_work (curl, ret_work)) {
		if ( improvável ((opt_retries> = 0 ) && (++ falhas> opt_retries))) {
			applog (LOG_ERR, " json_rpc_call falhou, encerrando o thread de trabalho " );
			livre (ret_work);
			return  false ;
		}

		/ * pausar e reiniciar o ciclo de solicitação de trabalho * /
		applog (LOG_ERR, " json_rpc_call falhou, tente novamente após % d segundos " ,
			opt_fail_pause);
		dormir (opt_fail_pause);
	}

	/ * enviar trabalho para o tópico solicitante * /
	if (! tq_push (wc-> thr -> q , ret_work))
		livre (ret_work);

	return  true ;
}

estático  bool  workio_submit_work ( struct workio_cmd * wc, CURL * curl)
{
	falhas internas = 0 ;

	/ * enviar solução para bitcoin via JSON-RPC * /
	while (! submit_upstream_work (curl, wc-> u . work )) {
		if ( improvável ((opt_retries> = 0 ) && (++ falhas> opt_retries))) {
			applog (LOG_ERR, " ... encerrando o thread de trabalho " );
			return  false ;
		}

		/ * pausar e reiniciar o ciclo de solicitação de trabalho * /
		applog (LOG_ERR, " ... tentar novamente após % d segundos " ,
			opt_fail_pause);
		dormir (opt_fail_pause);
	}

	return  true ;
}

static  void * workio_thread ( void * userdata)
{
	struct thr_info * mythr = userdata;
	CURL * curl;
	bool ok = verdadeiro ;

	curl = curl_easy_init ();
	if ( improvável (! curl)) {
		applog (LOG_ERR, " inicialização CURL falhou " );
		return  NULL ;
	}

	enquanto (ok) {
		struct workio_cmd * wc;

		/ * aguarde workio_cmd enviado para nós, em nossa fila * /
		wc = tq_pop (mythr-> q , NULL );
		if (! wc) {
			ok = falso ;
			pausa ;
		}

		/ * process workio_cmd * /
		switch (wc-> cmd ) {
		case WC_GET_WORK:
			ok = workio_get_work (wc, curl);
			pausa ;
		case WC_SUBMIT_WORK:
			ok = workio_submit_work (wc, curl);
			pausa ;

		padrão :		 / * nunca deve acontecer * /
			ok = falso ;
			pausa ;
		}

		workio_cmd_free (wc);
	}

	tq_freeze (mythr-> q );
	curl_easy_cleanup (curl);

	return  NULL ;
}

static  bool  get_work ( struct thr_info * thr, struct work * work)
{
	struct workio_cmd * wc;
	struct work * work_heap;

	if (opt_benchmark) {
		memset (trabalho-> dados , 0x55 , 76 );
		trabalho-> dados [ 17 ] = swab32 ( tempo ( NULL ));
		memset (trabalho-> dados + 19 , 0x00 , 52 );
		trabalho-> dados [ 20 ] = 0x80000000 ;
		trabalho-> dados [ 31 ] = 0x00000280 ;
		memset (trabalho-> alvo , 0x00 , sizeof (trabalho-> alvo ));
		return  true ;
	}

	/ * preencher mensagem de solicitação de trabalho * /
	wc = calloc ( 1 , sizeof (* wc));
	if (! wc)
		return  false ;

	wc-> cmd = WC_GET_WORK;
	wc-> thr = thr;

	/ * enviar solicitação de trabalho para thread de trabalho * /
	if (! tq_push (thr_info [work_thr_id]. q , wc)) {
		workio_cmd_free (wc);
		return  false ;
	}

	/ * espera por resposta, uma unidade de trabalho * /
	work_heap = tq_pop (thr-> q , NULL );
	if (! work_heap)
		return  false ;

	/ * copiar o trabalho devolvido para o armazenamento fornecido pelo chamador * /
	memcpy (trabalho, work_heap, sizeof (* trabalho));
	livre (work_heap);

	return  true ;
}

static  bool  submit_work ( struct thr_info * thr, const  struct work * work_in)
{
	struct workio_cmd * wc;
	
	/ * preencher mensagem de solicitação de trabalho * /
	wc = calloc ( 1 , sizeof (* wc));
	if (! wc)
		return  false ;

	wc-> u . work = malloc ( sizeof (* work_in));
	if (! wc-> u . work )
		goto err_out;

	wc-> cmd = WC_SUBMIT_WORK;
	wc-> thr = thr;
	work_copy (wc-> u . work , work_in);

	/ * enviar solução para thread de trabalho * /
	if (! tq_push (thr_info [work_thr_id]. q , wc))
		goto err_out;

	return  true ;

err_out:
	workio_cmd_free (wc);
	return  false ;
}

static  void  stratum_gen_work ( struct stratum_ctx * sctx, struct work * work)
{
	 char unsigned merkle_root [ 64 ];
	int i;

	pthread_mutex_lock (& sctx-> work_lock );

	livre (trabalho-> job_id );
work- 	> job_id = strdup (sctx-> job . job_id );
	trabalho-> xnonce2_len = sctx-> xnonce2_size ;
	trabalho-> xnonce2 = realloc (trabalho-> xnonce2 , sctx-> xnonce2_size );
	memcpy (trabalho-> xnonce2 , sctx-> trabalho . xnonce2 , sctx-> xnonce2_size );

	/ * Gerar raiz merkle * /
	sha256d (merkle_root, sctx-> job . coinbase , sctx-> job . coinbase_size );
	para (i = 0 ; i <sctx-> job . merkle_count ; i ++) {
		memcpy (merkle_root + 32 , sctx-> job . merkle [i], 32 );
		sha256d (merkle_root, merkle_root, 64 );
	}
	
	/ * Increment extranonce2 * /
	para (i = 0 ; i <sctx-> xnonce2_size &&! ++ sctx-> job . xnonce2 [i]; i ++);

	/ * Montar cabeçalho do bloco * /
	memset (trabalho-> dados , 0 , 128 );
	trabalho-> dados [ 0 ] = le32dec (sctx-> trabalho . versão );
	para (i = 0 ; i < 8 ; i ++)
		trabalho-> dados [ 1 + i] = le32dec (( uint32_t *) sctx-> trabalho . prevhash + i);
	para (i = 0 ; i < 8 ; i ++)
		trabalho-> dados [ 9 + i] = be32dec (( uint32_t *) merkle_root + i);
	trabalho-> dados [ 17 ] = le32dec (sctx-> trabalho . ntime );
	trabalho-> dados [ 18 ] = le32dec (sctx-> trabalho . nbits );
	trabalho-> dados [ 20 ] = 0x80000000 ;
	trabalho-> dados [ 31 ] = 0x00000280 ;

	pthread_mutex_unlock (& sctx-> work_lock );

	if (opt_debug) {
		char * xnonce2str = abin2hex (trabalho-> xnonce2 , trabalho-> xnonce2_len );
		applog (LOG_DEBUG, " DEBUG: job_id = ' % s ' extranonce2 = % s ntime = % 08x " ,
work- 		       > job_id , xnonce2str, swab32 ( work- > data [ 17 ]));
		livre (xnonce2str);
	}

	if (opt_algo == ALGO_SCRYPT)
		diff_to_target (trabalho-> destino , sctx-> trabalho . diff / 65536.0 );
	outro
		diff_to_target (trabalho-> alvo , sctx-> trabalho . diff );
}

static  void * miner_thread ( void * userdata)
{
	struct thr_info * mythr = userdata;
	int thr_id = mythr-> id ;
	estrutura trabalho trabalho = {{ 0 }};
	uint32_t max_nonce;
	uint32_t end_nonce = 0xffffffffU / opt_n_threads * (thr_id + 1 ) - 0x20 ;
	 char não assinado * scratchbuf = NULL ;
	char s [ 16 ];
	int i;

	/ * Definir threads de trabalho para nice 19 e preferencialmente para SCHED_IDLE
	 * e se isso falhar, então SCHED_BATCH. Não há necessidade de que isso seja um
	 * erro se falhar * /
	if (! opt_benchmark) {
		setpriority (PRIO_PROCESS, 0 , 19 );
		drop_policy ();
	}

	/ * A afinidade de CPU só faz sentido se o número de threads for um múltiplo
	 * do número de CPUs * /
	if (num_processors> 1 && opt_n_threads% num_processors == 0 ) {
		if (! opt_quiet)
			applog (LOG_INFO, " Encadeamento de ligação % d à cpu % d " ,
			       thr_id, thr_id% num_processors);
		affine_to_cpu (thr_id, thr_id% num_processors);
	}
	
	if (opt_algo == ALGO_SCRYPT) {
		scratchbuf = scrypt_buffer_alloc (opt_scrypt_n);
		if (! scratchbuf) {
			applog (LOG_ERR, " falha na alocação do buffer de criptografia " );
			pthread_mutex_lock (& applog_lock);
			saída ( 1 );
		}
	}

	enquanto ( 1 ) {
		 hashes_done longo sem sinal;
		struct  timeval tv_start, tv_end, diff;
		int64_t max64;
		int rc;

		if (have_stratum) {
			while ( time ( NULL )> = g_work_time + 120 )
				dormir ( 1 );
			pthread_mutex_lock (& g_work_lock);
			if (work. data [ 19 ]> = end_nonce &&! memcmp (work. data , g_work. data , 76 ))
				stratum_gen_work (& stratum, & g_work);
		} else {
			int min_scantime = have_longpoll? LP_SCANTIME: opt_scantime;
			/ * obter novo trabalho do thread de trabalho interno * /
			pthread_mutex_lock (& g_work_lock);
			if (! have_stratum &&
			    ( tempo ( NULL ) - g_work_time> = min_scantime ||
			     trabalhar. dados [ 19 ]> = end_nonce)) {
				work_free (& g_work);
				if ( improvável (! get_work (mythr, & g_work))) {
					applog (LOG_ERR, " recuperação de trabalho falhou, saindo "
						" segmento de mineração % d " , mythr-> id );
					pthread_mutex_unlock (& g_work_lock);
					goto out;
				}
				g_work_time = have_stratum? 0 : hora ( NULL );
			}
			if (have_stratum) {
				pthread_mutex_unlock (& g_work_lock);
				continue ;
			}
		}
		if ( memcmp (work. data , g_work. data , 76 )) {
			work_free (& work);
			work_copy (& work, & g_work);
			trabalhar. dados [ 19 ] = 0xffffffffU / opt_n_threads * thr_id;
		} mais
			trabalhar. dados [ 19 ] ++;
		pthread_mutex_unlock (& g_work_lock);
		work_restart [thr_id]. reiniciar = 0 ;
		
		/ * ajustar max_nonce para atingir o tempo de varredura alvo * /
		if (have_stratum)
			max64 = LP_SCANTIME;
		outro
			max64 = g_work_time + (have_longpoll? LP_SCANTIME: opt_scantime)
			      - tempo ( NULL );
		max64 * = thr_hashrates [thr_id];
		if (max64 <= 0 ) {
			switch (opt_algo) {
			case ALGO_SCRYPT:
				max64 = opt_scrypt_n < 16 ? 0x3ffff : 0x3fffff / opt_scrypt_n;
				pausa ;
			case ALGO_SHA256D:
				max64 = 0x1fffff ;
				pausa ;
			}
		}
		if (work. data [ 19 ] + max64> end_nonce)
			max_nonce = end_nonce;
		outro
			max_nonce = trabalho. dados [ 19 ] + máx64;
		
		hashes_done = 0 ;
		gettimeofday (& tv_start, NULL );

		/ * scan nonces para um hash de prova de trabalho * /
		switch (opt_algo) {
		case ALGO_SCRYPT:
			rc = scanhash_scrypt (thr_id, work. data , scratchbuf, work. target ,
			                     max_nonce, & hashes_done, opt_scrypt_n);
			pausa ;

		case ALGO_SHA256D:
			rc = scanhash_sha256d (thr_id, work. data , work. target ,
			                      max_nce, & hashes_done);
			pausa ;

		padrão :
			/ * nunca deveria acontecer * /
			goto out;
		}

		/ * registro do tempo decorrido do scanhash * /
		gettimeofday (& tv_end, NULL );
		timeval_subtract (& diff, & tv_end, & tv_start);
		if (diff. tv_usec || diff. tv_sec ) {
			pthread_mutex_lock (& stats_lock);
			thr_hashrates [thr_id] =
				hashes_done / (diff. tv_sec + 1e-6 * diff. tv_usec );
			pthread_mutex_unlock (& stats_lock);
		}
		if (! opt_quiet) {
			sprintf (s, thr_hashrates [thr_id]> = 1e6 ? " % .0f " : " % .2f " ,
				1e-3 * thr_hashrates [thr_id]);
			applog (LOG_INFO, " thread % d : % lu hashes, % s khash / s " ,
				thr_id, hashes_done, s);
		}
		if (opt_benchmark && thr_id == opt_n_threads - 1 ) {
			hashrate duplo = 0 .;
			para (i = 0 ; i <opt_n_threads && thr_hashrates [i]; i ++)
				hashrate + = thr_hashrates [i];
			if (i == opt_n_threads) {
				sprintf (s, hashrate> = 1e6 ? " % .0f " : " % .2f " , 1e-3 * hashrate);
				applog (LOG_INFO, " Total: % s khash / s " , s);
			}
		}

		/ * se o nonce for encontrado, envie o trabalho * /
		if (rc &&! opt_benchmark &&! submit_work (mythr, & work))
			pausa ;
	}

Fora:
	tq_freeze (mythr-> q );

	return  NULL ;
}

static  void  restart_threads ( void )
{
	int i;

	para (i = 0 ; i <opt_n_threads; i ++)
		work_restart [i]. reiniciar = 1 ;
}

static  void * longpoll_thread ( void * userdata)
{
	struct thr_info * mythr = userdata;
	CURL * curl = NULL ;
	char * copy_start, * hdr_path = NULL , * lp_url = NULL ;
	bool need_slash = false ;

	curl = curl_easy_init ();
	if ( improvável (! curl)) {
		applog (LOG_ERR, " inicialização CURL falhou " );
		goto out;
	}

começar:
	hdr_path = tq_pop (mythr-> q , NULL );
	if (! hdr_path)
		goto out;

	/ * URL completo * /
	if ( strstr (hdr_path, " : // " )) {
		lp_url = hdr_path;
		hdr_path = NULL ;
	}
	
	/ * caminho absoluto, no servidor atual * /
	else {
		copy_start = (* hdr_path == ' / ' )? (hdr_path + 1 ): hdr_path;
		if (rpc_url [ strlen (rpc_url) - 1 ]! = ' / ' )
			need_slash = true ;

		lp_url = malloc ( strlen (rpc_url) + strlen (iniciar_cópia) + 2 );
		if (! lp_url)
			goto out;

		sprintf (lp_url, " % s% s% s " , rpc_url, need_slash? " / " : " " , copy_start);
	}

	applog (LOG_INFO, " Long-polling ativado para % s " , lp_url);

	enquanto ( 1 ) {
		json_t * val, * res, * soval;
		char * req = NULL ;
		int err;

		if (have_gbt) {
			req = malloc ( strlen (gbt_lp_req) + strlen (lp_id) + 1 );
			sprintf (req, gbt_lp_req, lp_id);
		}
		val = json_rpc_call (curl, lp_url, rpc_userpass,
				    req? req: getwork_req, & err,
				    JSON_RPC_LONGPOLL);
		livre (req);
		if (have_stratum) {
			if (val)
				json_decref (val);
			goto out;
		}
		if ( provável (val)) {
			bool rc;
			applog (LOG_INFO, " LONGPOLL empurrou novo trabalho " );
			res = json_object_get (val, " resultado " );
			soval = json_object_get (res, " submitold " );
			submit_old = soval? json_is_true (aprovação): falso ;
			pthread_mutex_lock (& g_work_lock);
			work_free (& g_work);
			if (have_gbt)
				rc = gbt_work_decode (res, & g_work);
			outro
				rc = work_decode (res, & g_work);
			if (rc) {
				tempo (& g_work_time);
				restart_threads ();
			}
			pthread_mutex_unlock (& g_work_lock);
			json_decref (val);
		} else {
			pthread_mutex_lock (& g_work_lock);
			g_work_time - = LP_SCANTIME;
			pthread_mutex_unlock (& g_work_lock);
			if (errar == CURLE_OPERATION_TIMEDOUT) {
				restart_threads ();
			} else {
				have_longpoll = false ;
				restart_threads ();
				livre (hdr_path);
				grátis (lp_url);
				lp_url = NULL ;
				dormir (opt_fail_pause);
				goto start;
			}
		}
	}

Fora:
	livre (hdr_path);
	grátis (lp_url);
	tq_freeze (mythr-> q );
	if (curl)
		curl_easy_cleanup (curl);

	return  NULL ;
}

static  bool  stratum_handle_response ( char * buf)
{
	json_t * val, * err_val, * res_val, * id_val;
	json_error_t err;
	bool ret = falso ;

	val = JSON_LOADS (buf, & err);
	if (! val) {
		applog (LOG_INFO, " decodificação JSON falhou ( % d ): % s " , err. linha , err. texto );
		goto out;
	}

	res_val = json_object_get (val, " resultado " );
	err_val = json_object_get (val, " erro " );
	id_val = json_object_get (val, " id " );

	if (! id_val || json_is_null (id_val) ||! res_val)
		goto out;

	share_result ( json_is_true (res_val),
		err_val? json_string_value ( json_array_get (err_val, 1 )): NULL );

	ret = verdadeiro ;
Fora:
	if (val)
		json_decref (val);

	return ret;
}

static  void * stratum_thread ( void * userdata)
{
	struct thr_info * mythr = userdata;
	char * s;

	estrato. url = tq_pop (mythr-> q , NULL );
	if (! stratum. url )
		goto out;
	applog (LOG_INFO, " Iniciando estrato em % s " , estrato. url );

	enquanto ( 1 ) {
		falhas internas = 0 ;

		while (! stratum. curl ) {
			pthread_mutex_lock (& g_work_lock);
			g_work_time = 0 ;
			pthread_mutex_unlock (& g_work_lock);
			restart_threads ();

			if (! stratum_connect (& stratum, stratum. url ) ||
			    ! stratum_subscribe (& stratum) ||
			    ! stratum_authorize (& stratum, rpc_user, rpc_pass)) {
				stratum_disconnect (& stratum);
				if (opt_retries> = 0 && ++ failures> opt_retries) {
					applog (LOG_ERR, " ... encerrando o thread de trabalho " );
					tq_push (thr_info [work_thr_id]. q , NULL );
					goto out;
				}
				applog (LOG_ERR, " ... tentar novamente após % d segundos " , opt_fail_pause);
				dormir (opt_fail_pause);
			}
		}

		if (stratum. job . job_id &&
		    (! g_work_time || strcmp (stratum. job . job_id , g_work. job_id ))) {
			pthread_mutex_lock (& g_work_lock);
			stratum_gen_work (& stratum, & g_work);
			tempo (& g_work_time);
			pthread_mutex_unlock (& g_work_lock);
			if (stratum. job . clean ) {
				applog (LOG_INFO, " Stratum solicitou reinício do trabalho " );
				restart_threads ();
			}
		}
		
		if (! stratum_socket_full (& stratum, 120 )) {
			applog (LOG_ERR, "Tempo limite de conexão do Stratum esgotado " );
			s = NULL ;
		} mais
			s = stratum_recv_line (& stratum);
		if (! s) {
			stratum_disconnect (& stratum);
			applog (LOG_ERR, " conexão do Stratum interrompida " );
			continue ;
		}
		if (! stratum_handle_method (& stratum, s))
			stratum_handle_response (s);
		livre (s);
	}

Fora:
	return  NULL ;
}

static  void  show_version_and_exit ( void )
{
	printf (PACKAGE_STRING " \ n construído em " __DATE__ " \ n recursos: "
# se definido (USE_ASM) && definido (__ i386__)
		" i386 "
# endif
# se definido (USE_ASM) && definido (__ x86_64__)
		" x86_64 "
		" PHE "
# endif
# se definido (USE_ASM) && (definido (__ i386__) || definido (__ x86_64__))
		" SSE2 "
# endif
# se definido (__ x86_64__) && definido (USE_AVX)
		" AVX "
# endif
# se definido (__ x86_64__) && definido (USE_AVX2)
		" AVX2 "
# endif
# se definido (__ x86_64__) && definido (USE_XOP)
		" XOP "
# endif
# se definido (USE_ASM) && definido (__ arm__) && definido (__ APCS_32__)
		" ARM "
# se definido (__ ARM_ARCH_5E__) || definido (__ ARM_ARCH_5TE__) || \
	definido (__ARM_ARCH_5TEJ__) || definido (__ARM_ARCH_6__) || \
	definido (__ARM_ARCH_6J__) || definido (__ARM_ARCH_6K__) || \
	definido (__ARM_ARCH_6M__) || definido (__ARM_ARCH_6T2__) || \
	definido (__ARM_ARCH_6Z__) || definido (__ARM_ARCH_6ZK__) || \
	definido (__ARM_ARCH_7__) || \
	definido (__ARM_ARCH_7A__) || definido (__ARM_ARCH_7R__) || \
	definido (__ARM_ARCH_7M__) || definido (__ARM_ARCH_7EM__)
		" ARMv5E "
# endif
# se definido (__ ARM_NEON__)
		" NEON "
# endif
# endif
# se definido (USE_ASM) && (definido (__ powerpc__) || definido (__ ppc__) || definido (__ PPC__))
		" PowerPC "
# se definido (__ ALTIVEC__)
		" AltiVec "
# endif
# endif
		" \ n " );

	printf ( " % s \ n " , curl_version ());
# ifdef JANSSON_VERSION
	printf ( " libjansson % s \ n " , JANSSON_VERSION);
# endif
	saída ( 0 );
}

static  void  show_usage_and_exit ( int status)
{
	if (status)
		fprintf (stderr, " Tente` " PROGRAM_NAME " help' para obter mais informações. \ n " );
	outro
		printf (uso);
	saída (status);
}

 strhide vazio  estático ( char * s)
{
	if (* s) * s ++ = ' x ' ;
	while (* s) * s ++ = ' \ 0 ' ;
}

static  void  parse_config ( json_t * config, char * pname, char * ref);

static  void  parse_arg ( int key, char * arg, char * pname)
{
	char * p;
	int v, i;

	switch (chave) {
	case  ' a ' :
		para (i = 0 ; i < ARRAY_SIZE (algo_names); i ++) {
			v = strlen (algo_names [i]);
			if (! strncmp (arg, algo_names [i], v)) {
				if (arg [v] == ' \ 0 ' ) {
					opt_algo = i;
					pausa ;
				}
				if (arg [v] == ' : ' && i == ALGO_SCRYPT) {
					char * ep;
					v = strtol (arg + v + 1 , & ep, 10 );
					if (* ep || v & (v- 1 ) || v < 2 )
						continue ;
					opt_algo = i;
					opt_scrypt_n = v;
					pausa ;
				}
			}
		}
		if (i == ARRAY_SIZE (algo_names)) {
			fprintf (stderr, " % s : algoritmo desconhecido - ' % s ' \ n " ,
				pname, arg);
			show_usage_and_exit ( 1 );
		}
		pausa ;
	caso  ' B ' :
		opt_background = true ;
		pausa ;
	case  ' c ' : {
		json_error_t err;
		json_t * config = JSON_LOAD_FILE (arg, & err);
		if (! json_is_object (config)) {
			if (err. linha < 0 )
				fprintf (stderr, " % s : % s \ n " , pname, err. texto );
			outro
				fprintf (stderr, " % s : % s : % d : % s \ n " ,
					pname, arg, err. linha , err. texto );
			saída ( 1 );
		}
		parse_config (config, pname, arg);
		json_decref (config);
		pausa ;
	}
	case  ' q ' :
		opt_quiet = true ;
		pausa ;
	caso  ' D ' :
		opt_debug = true ;
		pausa ;
	case  ' p ' :
		livre (rpc_pass);
		rpc_pass = strdup (arg);
		strhide (arg);
		pausa ;
	caso  ' P ' :
		opt_protocol = true ;
		pausa ;
	case  ' r ' :
		v = atoi (arg);
		if (v <- 1 || v> 9999 )	 / * verificação de sanidade * /
			show_usage_and_exit ( 1 );
		opt_retries = v;
		pausa ;
	case  ' R ' :
		v = atoi (arg);
		if (v < 1 || v> 9999 )	 / * verificação de sanidade * /
			show_usage_and_exit ( 1 );
		opt_fail_pause = v;
		pausa ;
	case  ' s ' :
		v = atoi (arg);
		if (v < 1 || v> 9999 )	 / * verificação de sanidade * /
			show_usage_and_exit ( 1 );
		opt_scantime = v;
		pausa ;
	case  ' T ' :
		v = atoi (arg);
		if (v < 1 || v> 99999 )	 / * verificação de sanidade * /
			show_usage_and_exit ( 1 );
		opt_timeout = v;
		pausa ;
	case  ' t ' :
		v = atoi (arg);
		if (v < 1 || v> 9999 )	 / * verificação de sanidade * /
			show_usage_and_exit ( 1 );
		opt_n_threads = v;
		pausa ;
	case  ' u ' :
		livre (rpc_user);
		rpc_user = strdup (arg);
		pausa ;
	case  ' o ' : {			 / * --url * /
		char * ap, * hp;
		ap = strstr (arg, " : // " );
		ap = ap? ap + 3 : arg;
		hp = strrchr (arg, ' @ ' );
		if (hp) {
			* hp = ' \ 0 ' ;
			p = strchr (ap, ' : ' );
			if (p) {
				livre (rpc_userpass);
				rpc_userpass = strdup (ap);
				livre (rpc_user);
				rpc_user = calloc (p - ap + 1 , 1 );
				strncpy (rpc_user, ap, p - ap);
				livre (rpc_pass);
				rpc_pass = strdup (++ p);
				if (* p) * p ++ = ' x ' ;
				v = strlen (hp + 1 ) + 1 ;
				memmove (p + 1 , hp + 1 , v);
				memset (p + v, 0 , hp - p);
				hp = p;
			} else {
				livre (rpc_user);
				rpc_user = strdup (ap);
			}
			* hp ++ = ' @ ' ;
		} mais
			hp = ap;
		if (ap! = arg) {
			if ( strncasecmp (arg, " http: // " , 7 ) &&
			    strncasecmp (arg, " https: // " , 8 ) &&
			    strncasecmp (arg, " stratum + tcp: // " , 14 ) &&
			    strncasecmp (arg, " stratum + tcps: // " , 15 )) {
				fprintf (stderr, " % s : protocolo desconhecido - ' % s ' \ n " ,
					pname, arg);
				show_usage_and_exit ( 1 );
			}
			livre (rpc_url);
			rpc_url = strdup (arg);
			strcpy (rpc_url + (ap - arg), hp);
		} else {
			if (* hp == ' \ 0 ' || * hp == ' / ' ) {
				fprintf (stderr, " % s : URL inválido - ' % s ' \ n " ,
					pname, arg);
				show_usage_and_exit ( 1 );
			}
			livre (rpc_url);
			rpc_url = malloc ( strlen (hp) + 8 );
			sprintf (rpc_url, " http: // % s " , hp);
		}
		have_stratum =! opt_benchmark &&! strncasecmp (rpc_url, " stratum " , 7 );
		pausa ;
	}
	case  ' O ' :			 / * --userpass * /
		p = strchr (arg, ' : ' );
		if (! p) {
			fprintf (stderr, " % s : nome de usuário inválido: par de senha - ' % s ' \ n " ,
				pname, arg);
			show_usage_and_exit ( 1 );
		}
		livre (rpc_userpass);
		rpc_userpass = strdup (arg);
		livre (rpc_user);
		rpc_user = calloc (p - arg + 1 , 1 );
		strncpy (rpc_user, arg, p - arg);
		livre (rpc_pass);
		rpc_pass = strdup (++ p);
		strhide (p);
		pausa ;
	case  ' x ' :			 / * --proxy * /
		if (! strncasecmp (arg, " socks4: // " , 9 ))
			opt_proxy_type = CURLPROXY_SOCKS4;
		else  if (! strncasecmp (arg, " socks5: // " , 9 ))
			opt_proxy_type = CURLPROXY_SOCKS5;
# se LIBCURL_VERSION_NUM> = 0x071200
		else  if (! strncasecmp (arg, " socks4a: // " , 10 ))
			opt_proxy_type = CURLPROXY_SOCKS4A;
		else  if (! strncasecmp (arg, " socks5h: // " , 10 ))
			opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
# endif
		outro
			opt_proxy_type = CURLPROXY_HTTP;
		grátis (opt_proxy);
		opt_proxy = strdup (arg);
		pausa ;
	case  1001 :
		grátis (opt_cert);
		opt_cert = strdup (arg);
		pausa ;
	case  1005 :
		opt_benchmark = true ;
		want_longpoll = false ;
		want_stratum = false ;
		have_stratum = false ;
		pausa ;
	case  1003 :
		want_longpoll = false ;
		pausa ;
	case  1007 :
		want_stratum = false ;
		pausa ;
	case  1009 :
		opt_redirect = false ;
		pausa ;
	case  1010 :
		allow_getwork = false ;
		pausa ;
	case  1011 :
		have_gbt = false ;
		pausa ;
	case  1013 :			 / * --coinbase-addr * /
		pk_script_size = address_to_script (pk_script, sizeof (pk_script), arg);
		if (! pk_script_size) {
			fprintf (stderr, " % s : endereço inválido - ' % s ' \ n " ,
				pname, arg);
			show_usage_and_exit ( 1 );
		}
		pausa ;
	case  1015 :			 / * --coinbase-sig * /
		if ( strlen (arg) + 1 > sizeof (coinbase_sig)) {
			fprintf (stderr, " % s : assinatura coinbase muito longa \ n " , pname);
			show_usage_and_exit ( 1 );
		}
		strcpy (coinbase_sig, arg);
		pausa ;
	case  ' S ' :
		use_syslog = true ;
		pausa ;
	caso  ' V ' :
		show_version_and_exit ();
	case  ' h ' :
		show_usage_and_exit ( 0 );
	padrão :
		show_usage_and_exit ( 1 );
	}
}

static  void  parse_config ( json_t * config, char * pname, char * ref)
{
	int i;
	char * s;
	json_t * val;

	para (i = 0 ; i < ARRAY_SIZE (opções); i ++) {
		if (! opções [i]. nome )
			pausa ;

		val = json_object_get (configuração, opções [i]. nome );
		if (! val)
			continue ;

		if (options [i]. has_arg && json_is_string (val)) {
			if (! strcmp (options [i]. name , " config " )) {
				fprintf (stderr, " % s : % s : opção ' % s ' não permitida aqui \ n " ,
					pname, ref, options [i]. nome );
				saída ( 1 );
			}
			s = strdup ( json_string_value (val));
			se (! s)
				pausa ;
			parse_arg (opções [i]. val , s, pname);
			livre (s);
		} else  if (! options [i]. has_arg && json_is_true (val)) {
			parse_arg (opções [i]. val , " " , pname);
		} else {
			fprintf (stderr, " % s : argumento inválido para a opção ' % s ' \ n " ,
				pname, opções [i]. nome );
			saída ( 1 );
		}
	}
}

static  void  parse_cmdline ( int argc, char * argv [])
{
	chave int ;

	enquanto ( 1 ) {
# if HAVE_GETOPT_LONG
		key = getopt_long (argc, argv, short_options, options, NULL );
mais #
		key = getopt (argc, argv, short_options);
# endif
		if (chave < 0 )
			pausa ;

		parse_arg (chave, arg , argv [ 0 ]);
	}
	if ( optind <argc) {
		fprintf (stderr, " % s : argumento de opção não suportado - ' % s ' \ n " ,
			argv [ 0 ], argv [ optind ]);
		show_usage_and_exit ( 1 );
	}
}

# ifndef WIN32
static  void  signal_handler ( int sig)
{
	switch (sig) {
	case SIGHUP:
		applog (LOG_INFO, " SIGHUP recebido " );
		pausa ;
	case SIGINT:
		applog (LOG_INFO, " SIGINT recebido, saindo " );
		saída ( 0 );
		pausa ;
	case SIGTERM:
		applog (LOG_INFO, " SIGTERM recebido, saindo " );
		saída ( 0 );
		pausa ;
	}
}
# endif

int  main ( int argc, char * argv [])
{
	struct thr_info * thr;
	bandeiras longas ;
	int i;

	rpc_user = strdup ( " " );
	rpc_pass = strdup ( " " );

	/ * analisar linha de comando * /
	parse_cmdline (argc, argv);

	if (! opt_benchmark &&! rpc_url) {
		fprintf (stderr, " % s : nenhum URL fornecido \ n " , argv [ 0 ]);
		show_usage_and_exit ( 1 );
	}

	if (! rpc_userpass) {
		rpc_userpass = malloc ( strlen (rpc_user) + strlen (rpc_pass) + 2 );
		if (! rpc_userpass)
			return  1 ;
		sprintf (rpc_userpass, " % s : % s " , rpc_user, rpc_pass);
	}

	pthread_mutex_init (& applog_lock, NULL );
	pthread_mutex_init (& stats_lock, NULL );
	pthread_mutex_init (& g_work_lock, NULL );
	pthread_mutex_init (& stratum. sock_lock , NULL );
	pthread_mutex_init (& stratum. work_lock , NULL );

	flags = opt_benchmark || ( strncasecmp (rpc_url, " https: // " , 8 ) &&
	                          strncasecmp (rpc_url, " stratum + tcps: // " , 15 ))
	      ? (CURL_GLOBAL_ALL & ~ CURL_GLOBAL_SSL)
	      : CURL_GLOBAL_ALL;
	if ( curl_global_init (sinalizadores)) {
		applog (LOG_ERR, " inicialização CURL falhou " );
		return  1 ;
	}

# ifndef WIN32
	if (opt_background) {
		i = garfo ();
		se (i < 0 ) sair ( 1 );
		se (i> 0 ) sair ( 0 );
		i = setsid ();
		if (i < 0 )
			applog (LOG_ERR, " setsid () falhou (errno = % d ) " , errno);
		i = chdir ( " / " );
		if (i < 0 )
			applog (LOG_ERR, " chdir () falhou (errno = % d ) " , errno);
		sinal (SIGHUP, manipulador de sinal );
		sinal (SIGINT, signal_handler);
		sinal (SIGTERM, signal_handler);
	}
# endif

# se definido (WIN32)
	SYSTEM_INFO sysinfo;
	GetSystemInfo (& sysinfo);
	num_processors = sysinfo. dwNumberOfProcessors ;
# elif definido (_SC_NPROCESSORS_CONF)
	num_processors = sysconf (_SC_NPROCESSORS_CONF);
# elif definido (CTL_HW) && definido (HW_NCPU)
	req int [] = {CTL_HW, HW_NCPU};
	size_t len = sizeof (num_processors);
	sysctl (req, 2 , & num_processors, & len, NULL , 0 );
mais #
	num_processors = 1 ;
# endif
	if (num_processors < 1 )
		num_processors = 1 ;
	if (! opt_n_threads)
		opt_n_threads = num_processors;

# ifdef HAVE_SYSLOG_H
	if (use_syslog)
		openlog ( " cpuminer " , LOG_PID, LOG_USER);
# endif

	work_restart = calloc (opt_n_threads, sizeof (* work_restart));
	if (! work_restart)
		return  1 ;

	thr_info = calloc (opt_n_threads + 3 , sizeof (* thr));
	if (! thr_info)
		return  1 ;
	
	thr_hashrates = ( double *) calloc (opt_n_threads, sizeof ( double ));
	if (! thr_hashrates)
		return  1 ;

	/ * informações do thread do init workio * /
	work_thr_id = opt_n_threads;
	thr = & thr_info [work_thr_id];
	thr-> id = work_thr_id;
	thr-> q = tq_new ();
	if (! thr-> q )
		return  1 ;

	/ * iniciar o thread de E / S de trabalho * /
	se ( pthread_create (& Thr-> PTH , NULL , workio_thread, THR)) {
		applog (LOG_ERR, " falha na criação do thread de trabalho " );
		return  1 ;
	}

	if (want_longpoll &&! have_stratum) {
		/ * informações do thread do init longpoll * /
		longpoll_thr_id = opt_n_threads + 1 ;
		thr = & thr_info [longpoll_thr_id];
		thr-> id = longpoll_thr_id;
		thr-> q = tq_new ();
		if (! thr-> q )
			return  1 ;

		/ * start longpoll thread * /
		se ( improvável ( pthread_create (& Thr-> PTH , NULL , longpoll_thread, THR))) {
			applog (LOG_ERR, " longpoll thread create failed " );
			return  1 ;
		}
	}
	if (want_stratum) {
		/ * init stratum thread info * /
		stratum_thr_id = opt_n_threads + 2 ;
		thr = & thr_info [stratum_thr_id];
		thr-> id = stratum_thr_id;
		thr-> q = tq_new ();
		if (! thr-> q )
			return  1 ;

		/ * start stratum thread * /
		se ( improvável ( pthread_create (& Thr-> PTH , NULL , stratum_thread, THR))) {
			applog (LOG_ERR, " stratum thread create failed " );
			return  1 ;
		}

		if (have_stratum)
			tq_push (thr_info [stratum_thr_id]. q , strdup (rpc_url));
	}

	/ * iniciar a mineração de threads * /
	para (i = 0 ; i <opt_n_threads; i ++) {
		thr = & thr_info [i];

		thr-> id = i;
		thr-> q = tq_new ();
		if (! thr-> q )
			return  1 ;

		se ( improvável ( pthread_create (& Thr-> PTH , NULL , miner_thread, THR))) {
			applog (LOG_ERR, " thread % d criação falhou " , i);
			return  1 ;
		}
	}

	applog (LOG_INFO, " % d tópicos de mineração iniciados, "
		" usando o algoritmo ' % s '. " ,
		opt_n_threads,
		algo_names [opt_algo]);

	/ * loop principal - simplesmente espere que a thread de trabalho saia * /
	pthread_join (thr_info [work_thr_id]. PTH , NULL );

	applog (LOG_INFO, " thread de trabalho inoperante, saindo. " );

	return  0 ;
}
