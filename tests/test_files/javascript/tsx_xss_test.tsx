export const onRendererLoad = ({
  ipc: { invoke, on },
}: RendererContext<LyricsGeniusPluginConfig>) => {
  const setLyrics = (lyricsContainer: Element, lyrics: string | null) => {
    const targetHtml = `
      <div id="contents" class="style-scope ytmusic-section-list-renderer description ytmusic-description-shelf-renderer genius-lyrics">
        ${
          lyrics?.replaceAll(/\r\n|\r|\n/g, '<br/>') ??
          'Could not retrieve lyrics from genius'
        }
      </div>
      <yt-formatted-string class="footer style-scope ytmusic-description-shelf-renderer" style="align-self: baseline">
      </yt-formatted-string>
    `;
    (lyricsContainer.innerHTML as string | TrustedHTML) =
      defaultTrustedTypePolicy
        ? defaultTrustedTypePolicy.createHTML(targetHtml)
        : targetHtml;

    if (lyrics) {
      const footer = lyricsContainer.querySelector('.footer');

      if (footer) {
        footer.textContent = 'Source: Genius';
      }
    }
  };
}; 