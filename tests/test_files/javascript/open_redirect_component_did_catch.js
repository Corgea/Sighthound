// Test file for CWE-601 Open Redirect via componentDidCatch pattern
// This pattern stores localStorage data in React state, which could later be used for redirection

// ===== VULNERABLE PATTERNS (Should be detected) =====

// 1. Original componentDidCatch pattern from user
class ErrorBoundary extends React.Component {
  componentDidCatch(error, errorInfo) {
    const _localStorage = {};
    for (const [key, value] of Object.entries({ ...localStorage })) {
      try {
        _localStorage[key] = JSON.parse(value);
      } catch (error) {
        _localStorage[key] = value;
      }
    }

    Sentry.withScope((scope) => {
      scope.setExtras(errorInfo);
      const eventId = Sentry.captureException(error);

      // VULNERABLE: localStorage data flows to setState
      this.setState((state) => ({
        hasError: true,
        sentryEventId: eventId,
        localStorage: JSON.stringify(_localStorage), // CWE-601 risk
      }));
    });
  }
}

// 2. Direct localStorage spread to setState
class DirectSpreadComponent extends React.Component {
  handleError() {
    const data = { ...localStorage };
    this.setState({ data }); // VULNERABLE: localStorage → setState
  }
}

// 3. localStorage.getItem to setState
class DirectGetItemComponent extends React.Component {
  componentDidMount() {
    const redirectUrl = localStorage.getItem('redirectUrl');
    this.setState({ redirectUrl }); // VULNERABLE: localStorage → setState
  }
}

// 4. URL params to setState
class UrlParamsComponent extends React.Component {
  componentDidMount() {
    const params = new URLSearchParams(window.location.search);
    const nextUrl = params.get('next');
    this.setState({ nextUrl }); // VULNERABLE: URL params → setState
  }
}

// 5. PostMessage to setState
class PostMessageComponent extends React.Component {
  componentDidMount() {
    window.addEventListener('message', (event) => {
      this.setState({ redirectTarget: event.data.redirect }); // VULNERABLE: PostMessage → setState
    });
  }
}

// 6. Network response to setState
class NetworkResponseComponent extends React.Component {
  async fetchData() {
    const response = await fetch('/api/data');
    const data = await response.json();
    this.setState({ redirectUrl: data.redirectUrl }); // VULNERABLE: Network response → setState
  }
}

// 7. Form input to setState
class FormInputComponent extends React.Component {
  handleSubmit() {
    const input = document.getElementById('redirectInput').value;
    this.setState({ redirectUrl: input }); // VULNERABLE: Form input → setState
  }
}

// ===== SAFE PATTERNS (Should NOT be detected) =====

// 1. Static values in setState
class SafeStaticComponent extends React.Component {
  handleError() {
    this.setState({ 
      hasError: true,
      message: 'An error occurred',
      redirectUrl: '/dashboard' // Safe: static value
    });
  }
}

// 2. Validated URLs in setState
class SafeValidatedComponent extends React.Component {
  handleRedirect() {
    const url = localStorage.getItem('redirectUrl');
    if (isValidURL(url) && allowedDomains.includes(getDomain(url))) {
      this.setState({ redirectUrl: url }); // Safe: validated URL
    }
  }
}

// 3. Relative URLs in setState
class SafeRelativeComponent extends React.Component {
  handleRedirect() {
    const path = localStorage.getItem('path');
    if (path && path.startsWith('/')) {
      this.setState({ redirectUrl: path }); // Safe: relative URL
    }
  }
}

// 4. Sanitized data in setState
class SafeSanitizedComponent extends React.Component {
  handleData() {
    const data = sanitizeData(localStorage.getItem('data'));
    this.setState({ data }); // Safe: sanitized data
  }
} 