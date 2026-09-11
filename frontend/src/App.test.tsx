import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import App from './App'

describe('App', () => {
  it('identifies the product and empty scan state', () => {
    render(<App />)

    expect(screen.getByRole('heading', { name: 'DPMAP' })).toBeInTheDocument()
    expect(screen.getByText('No scan batches yet')).toBeInTheDocument()
  })
})

