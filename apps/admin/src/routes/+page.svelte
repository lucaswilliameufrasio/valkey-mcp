<script lang="ts">
  import { session } from '$lib/session.svelte';
</script>

<svelte:head><title>Visão geral · Valkey MCP</title></svelte:head>

<div class="page-heading">
  <div>
    <p class="eyebrow">VALKEY / PLANO DE CONTROLE</p>
    <h1>Visão geral<span class="heading-period">.</span></h1>
    <p class="page-lede">
      Controle de conexões, grants por prefixo de chave e operações autorizadas.
    </p>
  </div>
  {#if session.currentPrincipal?.platform_role === 'admin'}
    <a class="button button-primary" href="/valkey">Gerenciar conexões e acessos</a>
  {/if}
</div>

<section class="overview-hero panel" aria-labelledby="access-model-title">
  <div>
    <p class="eyebrow">MODELO DE AUTORIZAÇÃO</p>
    <h2 id="access-model-title">Acesso explícito. Prefixos definidos.</h2>
    <p>
      Cada grant associa uma pessoa a uma conexão e ao prefixo de chaves permitido. Escrita e
      exclusão exigem autorização explícita.
    </p>
  </div>
  <div class="overview-hero-mark" aria-hidden="true">KEY<span>SPACE</span></div>
</section>

<section class="overview-grid" aria-label="Áreas de administração">
  <article class="panel overview-card">
    <p class="eyebrow">CONEXÕES</p>
    <h2>Destinos Valkey</h2>
    <p>Cadastre endpoints e mantenha credenciais fora do catálogo operacional.</p>
    {#if session.currentPrincipal?.platform_role === 'admin'}
      <a href="/valkey">Abrir configuração <span aria-hidden="true">↗</span></a>
    {:else}
      <span class="overview-note">A configuração é gerenciada por administradores.</span>
    {/if}
  </article>
  <article class="panel overview-card">
    <p class="eyebrow">ESCOPO</p>
    <h2>Grants por prefixo</h2>
    <p>Delimite as chaves acessíveis e conceda o nível de operação necessário.</p>
    <span class="scope-example">cache:catalog:* <span>somente com grant</span></span>
  </article>
  <article class="panel overview-card">
    <p class="eyebrow">RASTREABILIDADE</p>
    <h2>Eventos de auditoria</h2>
    <p>Consulte tentativas permitidas, negadas e falhas registradas pelo gateway.</p>
    <a href="/audit">Consultar auditoria <span aria-hidden="true">↗</span></a>
  </article>
</section>

<style>
  .overview-hero {
    display: flex;
    min-height: 190px;
    align-items: center;
    justify-content: space-between;
    gap: 28px;
    border-left: 3px solid var(--product-accent);
  }
  .overview-hero > div:first-child {
    max-width: 670px;
  }
  .overview-hero h2 {
    margin: 8px 0;
    font-size: clamp(21px, 2.5vw, 28px);
  }
  .overview-hero p:not(.eyebrow) {
    margin: 0;
    color: var(--muted);
    font-size: 13px;
    line-height: 1.7;
  }
  .overview-hero-mark {
    flex: 0 0 auto;
    color: #a0442e;
    font-family: var(--mono);
    font-size: clamp(20px, 3.6vw, 34px);
    font-weight: 700;
    letter-spacing: -0.08em;
  }
  .overview-hero-mark span {
    color: #d6a193;
  }
  .overview-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 14px;
    margin-top: 14px;
  }
  .overview-card {
    display: flex;
    min-height: 210px;
    flex-direction: column;
    align-items: flex-start;
  }
  .overview-card h2 {
    margin: 7px 0;
  }
  .overview-card > p:not(.eyebrow) {
    margin: 0 0 18px;
    color: var(--muted);
    font-size: 12px;
    line-height: 1.65;
  }
  .overview-card a {
    margin-top: auto;
    color: var(--product-accent-strong);
    font-size: 11px;
    font-weight: 650;
  }
  .overview-note {
    margin-top: auto;
    color: var(--muted);
    font-size: 10px;
  }
  .scope-example {
    margin-top: auto;
    padding: 7px 9px;
    border: 1px solid #dce4e8;
    border-radius: 4px;
    background: #f6f8f9;
    color: #334c62;
    font-family: var(--mono);
    font-size: 10px;
  }
  .scope-example span {
    color: #71818a;
    font-family: Inter, sans-serif;
  }
  @media (max-width: 780px) {
    .overview-grid {
      grid-template-columns: 1fr;
    }
    .overview-card {
      min-height: 170px;
    }
  }
  @media (max-width: 500px) {
    .overview-hero-mark {
      display: none;
    }
  }
</style>
