<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import {
    clearSessionError,
    initializeSession,
    session,
    signIn,
    signOut
  } from '$lib/session.svelte';
  import '../app.css';

  let { children } = $props();
  let loginBusy = $state(false);
  let loginMessage = $state<string | undefined>();

  onMount(() => {
    void initializeSession();
  });

  async function handleSignIn(): Promise<void> {
    loginBusy = true;
    loginMessage = undefined;
    clearSessionError();
    try {
      await signIn();
    } catch {
      loginMessage = 'Não foi possível iniciar o login. Verifique a configuração OIDC.';
      loginBusy = false;
    }
  }

  async function handleSignOut(): Promise<void> {
    await signOut();
  }
</script>

<svelte:head>
  <title>Valkey MCP</title>
  <meta name="description" content="Administração de acesso controlado ao Valkey via MCP" />
</svelte:head>

{#if session.isInitializing}
  <main class="boot-screen" aria-live="polite">
    <div class="boot-mark">VK</div>
    <p>Conectando ao plano de controle</p>
  </main>
{:else if !session.currentPrincipal}
  <main class="login-screen" data-product="valkey">
    <section class="login-card">
      <div class="brand-lockup">
        <div class="brand-mark">VK</div>
        <div>
          <p class="eyebrow">VALKEY MCP</p>
          <p class="brand-subtitle">Acesso ao keyspace</p>
        </div>
      </div>
      <div class="login-copy">
        <p class="eyebrow">ACESSO CORPORATIVO</p>
        <h1>Chaves acessíveis<br />por autorização.</h1>
        <p>
          Entre com a identidade corporativa. O acesso a conexões e prefixos é concedido
          individualmente e auditado.
        </p>
      </div>
      {#if session.sessionError || loginMessage}
        <p class="notice notice-error" role="alert">{loginMessage ?? session.sessionError}</p>
      {/if}
      <button class="button button-primary button-wide" onclick={handleSignIn} disabled={loginBusy}>
        {loginBusy ? 'Redirecionando…' : 'Entrar com SSO'}
        <span aria-hidden="true">↗</span>
      </button>
      <p class="login-footnote">A autenticação é feita pelo seu provedor OIDC.</p>
    </section>
    <aside class="login-aside" data-product="valkey" aria-hidden="true">
      <div class="signal-grid"></div>
      <div class="aside-caption">
        <span class="status-dot"></span>
        <span>REDE PRIVADA · ACESSO AUDITÁVEL</span>
      </div>
      <div class="aside-message">
        <p class="eyebrow">VALKEY MCP</p>
        <p>Identidade, grant e prefixo de chaves.</p>
      </div>
      <div class="aside-meta"><span>Identidade</span><span>Grant</span><span>Prefixo</span></div>
    </aside>
  </main>
{:else}
  <div class="application-shell" data-product="valkey">
    <aside class="sidebar">
      <a class="brand-lockup sidebar-brand" href="/" aria-label="Valkey MCP — início">
        <div class="brand-mark">VK</div>
        <div>
          <p class="eyebrow">VALKEY MCP</p>
          <p class="brand-subtitle">Plano de controle</p>
        </div>
      </a>
      <div class="sidebar-label">WORKSPACE</div>
      <nav aria-label="Navegação principal">
        <a class:active={page.url.pathname === '/'} href="/">
          <span class="nav-icon" aria-hidden="true">OV</span><span>Visão geral</span>
        </a>
        {#if session.currentPrincipal.platform_role === 'admin'}
          <a class:active={page.url.pathname.startsWith('/valkey')} href="/valkey">
            <span class="nav-icon" aria-hidden="true">VK</span><span>Valkey</span>
          </a>
          <a class:active={page.url.pathname.startsWith('/audit')} href="/audit">
            <span class="nav-icon" aria-hidden="true">LOG</span><span>Auditoria</span>
          </a>
        {/if}
      </nav>
      <div class="sidebar-bottom">
        <div class="network-chip"><span class="status-dot"></span> Valkey MCP privado</div>
        <div class="user-card">
          <div class="avatar">
            {(session.currentPrincipal.display_name ?? session.currentPrincipal.email ?? 'U')
              .slice(0, 1)
              .toUpperCase()}
          </div>
          <div class="user-details">
            <strong
              >{session.currentPrincipal.display_name ??
                session.currentPrincipal.email ??
                session.currentPrincipal.subject}</strong
            >
            <span
              >{session.currentPrincipal.platform_role === 'admin'
                ? 'Administrador'
                : 'Membro'}</span
            >
          </div>
          <button class="icon-button" aria-label="Sair" title="Sair" onclick={handleSignOut}
            >↗</button
          >
        </div>
      </div>
    </aside>
    <main class="main-panel">
      <header class="topbar">
        <span
          >PLANO DE CONTROLE <span class="crumb-separator">/</span>
          {page.url.pathname === '/' ? 'INÍCIO' : page.url.pathname.slice(1).toUpperCase()}</span
        >
        <div class="topbar-state"><span class="status-dot"></span> Serviço conectado</div>
      </header>
      <div class="page-content">{@render children()}</div>
    </main>
  </div>
{/if}
