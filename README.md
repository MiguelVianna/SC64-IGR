# SC64-IGR — beta comunitário para SummerCart64

**Para voltar à lista de jogos, segure L + R + START ao mesmo tempo por
2 a 3 segundos. Não basta apertar e soltar: mantenha os três botões pressionados.**

Assim você pode trocar de jogo sem levantar para apertar RESET a cada teste.

O projeto nasceu da vontade de facilitar sessões em que testamos vários jogos.
O retorno pelo controle já é uma comodidade comum em outros sistemas; esta
adaptação procura oferecer essa experiência no Nintendo64 com SummerCart64.

**Este é um projeto inicial, em fase beta. Pode conter erros, travamentos e
incompatibilidades. Não há garantia de funcionamento em todos os jogos.**
É uma modificação comunitária do N64FlashcartMenu0.3.5, não uma versão oficial
dos autores do menu original ou do SummerCart64.

## Agradecimento aos criadores do menu e do SummerCart64

Este projeto só existe graças ao **[N64FlashcartMenu](https://github.com/n64brew/N64FlashcartMenu)**,
criado e mantido por **Mateusz Faderewski (Polprzewodnikowy), Robin Jones
(NetworkFusion) e todos os seus colaboradores**, e ao trabalho do
**[SummerCart64](https://github.com/Polprzewodnikowy/SummerCart64)** e de sua comunidade.
**Muito obrigado por criarem e compartilharem esses projetos.**

O menu-base desta adaptação é o **N64FlashcartMenu 0.3.5**, sob licença
**GNU AGPLv3**. Não reivindicamos a autoria do menu original, do hardware,
do firmware ou das bibliotecas e recursos de terceiros. Aqui são documentadas
as alterações comunitárias para acrescentar e adaptar o IGR.

[Créditos completos, dependências e licenças](CREDITOS.md) ·
[Todos os colaboradores do menu original](https://github.com/n64brew/N64FlashcartMenu/graphs/contributors).

## Download — v0.1.0-beta.1

**[Baixar sc64menu.n64 pronto](downloads/sc64menu.n64?raw=true)**

[Gerador HTML offline](downloads/GERAR_MENU.html?raw=true) ·
[Notas da versão](docs/NOTAS_DA_VERSAO.md) ·
[Compatibilidade e limitações](docs/COMPATIBILIDADE.md) ·
[Créditos e licença](CREDITOS.md)

Esta adaptação do IGR destina-se ao **SummerCart64 em Nintendo64 com Expansion
Pak instalado**. O retorno depende do hardware/bootloader do SummerCart64;
não há suporte anunciado para EverDrive ou64drive. Sem Expansion Pak,
o motor de IGR não é instalado.

## Instalação e uso

1. Guarde uma cópia do seu menu atual para poder voltar a ele.
2. Baixe `sc64menu.n64` e coloque-o na raiz do cartãoSD do SummerCart64,
   substituindo o menu anterior.
3. Ligue o console e abra o jogo normalmente, sem segurar CIMA.
4. Para voltar à lista, **mantenha L + R + START pressionados juntos por
   2 a 3 segundos**. O tempo total do retorno pode variar entre os jogos.

O arquivo é um menu para o cartucho; não é uma atualização de firmware.
Não acione o retorno enquanto o jogo estiver gravando dados.

## Tela preta ou travamento ao abrir um jogo

1. Reinicie o console pelo botãoRESET. Se o console não responder, desligue-o
   e ligue-o novamente.
2. Escolha novamente o jogo.
3. Na última confirmação de início, **comece a segurar CIMA no direcional
   digital e mantenha durante a barra de carregamento, até o jogo iniciar**.
   Use o D-pad, não o analógico.

Isso desativa o IGR **apenas nesse lançamento**, permitindo testar o jogo pelo
caminho sem a adaptação. Para tentar com IGR novamente, abra sem segurar CIMA.
Esse escape não corrige defeitos do arquivo do jogo ou outras incompatibilidades
do cartucho/menu.

## Por que alguns jogos precisam de ajustes próprios?

Os jogos não organizam a memória da mesma forma. Alguns medem a RAM por conta
própria, reservam toda a memória extra, instalam suas próprias rotinas de
interrupção ou alteram o mecanismo usado pelo IGR. A volta também depende de
encerrar corretamente as tarefas de vídeo e outros periféricos.

Por isso, uma única abordagem ainda não cobre toda a biblioteca: certos jogos
precisam de estudo e adaptação por título e revisão. Um jogo pode abrir e o
IGR não responder; em outro, a adaptação pode impedir a abertura. Há também
revisões que ficam deliberadamente sem IGR até receberem uma ligação segura.

## Compatibilidade e colaboração

Há relatos positivos com Zelda, Banjo, Mario e vários títulos da Rare. Entre
os ajustes específicos confirmados em console estão Majora's Mask, Donkey Kong64,
Perfect Dark americano1.1,1080°, Indiana Jones e Fighter Destiny2.
**Isso não certifica todas as regiões, revisões, hacks, modos ou fases.**

Se um jogo falhar, abra uma **Issue → Incompatibilidade de IGR** neste repositório.
Informe o nome completo, região/revisão, versão deste beta, hardware e o que
acontece com e sem CIMA. Se possível, inclua o hash do arquivo e foto/vídeo do
problema. Não envie ROMs de jogos na Issue.

Relatos detalhados ajudam a reproduzir as falhas e preparar atualizações sem
perder o que já funciona. Ainda não existe uma lista exaustiva de compatibilidade
nem prazo garantido para cada adaptação.

## Fontes, reprodução e integridade

- [Fontes da adaptação](src/) e [como reproduzir a versão](docs/REPRODUZIR.md).
- [Fontes do menu-base0.3.5 com submódulos](downloads/N64FlashcartMenu-V0.3.5-fontes.zip?raw=true).
- [Licença GNU AGPLv3](LICENSE.md), [créditos](CREDITOS.md) e
  [proveniência com commits](docs/PROVENIENCIA.json).
- [SHA256 dos downloads](downloads/SHA256SUMS.txt).

O SHA256 do menu deste beta é:

```text
719be9a6f7d646d08fcf8848b5a6d8d346d90d5b1dcbb4502812645d56093e11
```

Nenhuma ROM de jogo comercial faz parte desta distribuição.
