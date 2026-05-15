'use client';
import { Component, ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        this.props.fallback ?? (
          <div className="p-6 rounded-lg border border-red-500/20 bg-red-500/10">
            <p className="text-red-400 font-medium">Something went wrong</p>
            <p className="text-sm text-zinc-400 mt-1">{this.state.error.message}</p>
            <button
              onClick={() => this.setState({ error: null })}
              className="mt-3 text-sm text-zinc-300 underline"
            >
              Try again
            </button>
          </div>
        )
      );
    }
    return this.props.children;
  }
}
