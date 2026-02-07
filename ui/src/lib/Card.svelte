<script lang="ts">
  import type { Branding } from './types'
  import type { Snippet } from 'svelte'

  interface Props {
    branding: Branding
    children: Snippet
  }

  let { branding, children }: Props = $props()
</script>

<div class="card">
  {#if branding.logoUrl}
    <div class="logo">
      <img src={branding.logoUrl} alt="Logo" />
    </div>
  {/if}
  {@render children()}
</div>

<style>
  .card {
    background: var(--card-background, white);
    border-radius: 8px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    padding: 40px;
    width: 100%;
    max-width: 400px;
  }

  .logo {
    text-align: center;
    margin-bottom: 24px;
  }

  .logo img {
    max-width: 150px;
    max-height: 60px;
  }
</style>
