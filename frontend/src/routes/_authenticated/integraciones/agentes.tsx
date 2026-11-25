import { createFileRoute } from '@tanstack/react-router'
import { Agentes } from '@/features/agentes'

export const Route = createFileRoute('/_authenticated/integraciones/agentes')({
  component: Agentes,
})
