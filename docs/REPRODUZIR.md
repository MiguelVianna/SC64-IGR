# Fontes e reprodução da versão

## Gerar exatamente o arquivo publicado

1. Obtenha o [menu oficial N64FlashcartMenu0.3.5](https://github.com/n64brew/N64FlashcartMenu/releases/tag/V0.3.5), arquivo `N64FlashcartMenu.n64`.
2. Confira o SHA256 da entrada:
   `c4684d1cea72c708ae1cac7199138b863c942356dc72b10166e3286a452bb3d0`.
3. Salve e abra [GERAR_MENU.html](../downloads/GERAR_MENU.html?raw=true) no
   navegador e escolha esse arquivo. Não é necessário enviar o menu pela internet.
4. A saída deve ter1769472bytes e SHA256
   `719be9a6f7d646d08fcf8848b5a6d8d346d90d5b1dcbb4502812645d56093e11`.

O HTML contém JavaScript legível, guardas de entrada e os dados de patch próprios.
O binário oficial não está embutido nele. Aceita também determinadas versões
anteriores deste projeto, identificadas por hash. Não aplica alterações em
arquivos desconhecidos nem altera o arquivo escolhido.

## Fontes nativos e upstream

[src/](../src/) contém os módulos Python usados para gerar o códigoMIPS e a
cave desta versão, incluindo o builder final `build_fighter_destiny2_candidate.py`.
Esse builder interno recebe a V25 intermediária exata; o HTML faz a cadeia
desde o menu oficial e é o procedimento completo para reproduzir esta entrega.

O [arquivo de fontes upstream](../downloads/N64FlashcartMenu-V0.3.5-fontes.zip?raw=true)
contém os fontes de compilação0.3.5, bibliotecas/submódulos nas revisões referenciadas,
licenças, assets públicos do próprio menu, Makefile e configuração de toolchain.
Não contém ROMs comerciais. A lista de commits está em[PROVENIENCIA.json](PROVENIENCIA.json).

Para estudar/compilar o menu-base, extraia o ZIP e siga o README/Makefile e
`.devcontainer/ci` nele incluídos. Para consultar o histórico original:

```sh
git clone --branch V0.3.5 --recurse-submodules https://github.com/n64brew/N64FlashcartMenu.git
```

Compilar os fontes upstream com ferramentas ou timestamps diferentes pode
produzir outro binário. A adaptação por offsets rejeita esse resultado em vez
de assumir que é igual ao oficial. A reprodução byte a byte oferecida aqui usa
o binário oficial identificado acima e as alterações inteiramente descritas
no HTML/fontes. Não foi alegada nova compilação completa do menu nesta publicação.

O pacote omite vetores de teste, testes externos e exemplos não necessários à compilação do menu. Os caminhos omitidos estão na proveniência; permanecem acessíveis nos projetos originais e commits indicados. Compile libdragon com `./build.sh --no-examples`, como na configuração upstream.
